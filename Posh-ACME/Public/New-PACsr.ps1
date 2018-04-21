#using namespace Org.BouncyCastle.Asn1
#using namespace Org.BouncyCastle.Asn1.Nist
#using namespace Org.BouncyCastle.Asn1.Pkcs
#using namespace Org.BouncyCastle.Asn1.X509
#using namespace Org.BouncyCastle.Crypto
#using namespace Org.BouncyCastle.Crypto.Generators
#using namespace Org.BouncyCastle.Crypto.Parameters
#using namespace Org.BouncyCastle.Pkcs
#using namespace Org.BouncyCastle.Security
#using namespace Org.BouncyCastle.X509.Extension

function New-PACsr {
    [CmdletBinding()]
    [OutputType('System.String')]
    param(
        [Parameter(Mandatory,Position=0)]
        [string[]]$Domain,

        [Parameter(ParameterSetName='NewKey',Position=1)]
        [ValidateScript({Test-ValidKeyLength $_ -ThrowOnFail})]
        [string]$KeyLength='4096',

        # [Parameter(ParameterSetName='OldKey',Position=1)]
        # [ValidateScript({Test-ValidKey $_ -ThrowOnFail})]
        # [Security.Cryptography.AsymmetricAlgorithm]$Key

        [switch]$OCSPMustStaple,
        [Parameter(Mandatory)]
        [string]$OutputFolder
    )

    # Unfortunately, the .NET managed X509 classes aren't quite there yet in terms of the functionality
    # we need. There's a new CertificateRequest class in .NET Core 2.0, but it won't be in the full
    # .NET Framework until 4.7.2 which is still in preview and who knows what the platform requirements
    # will be when they release. The legacy CertEnroll COM APIs are an option but my first attempt at
    # at working with them ultimately ended in failure and they felt too tightly coupled to the Windows
    # cert store. I contemplated just shell'ing out to certreq.exe and certutil.exe, but they're just
    # not granular enough to do what I want to do.

    # So for now, we're going to leverage the .NET version of the Bouncy Castle libraries. It's a binary
    # dependency I was hoping to avoid. But it seems like the best option until the native BCL matures.

    # create the private key if necessary
    if ('NewKey' -eq $PSCmdlet.ParameterSetName) {

        $sRandom = New-Object Org.BouncyCastle.Security.SecureRandom

        if ($KeyLength -like 'ec-*') {

            Write-Verbose "Creating BC EC keypair of type $KeyLength"
            $isRSA = $false
            $keySize = [int]$KeyLength.Substring(3)
            $curveOid = [Org.BouncyCastle.Asn1.Nist.NistNamedCurves]::GetOid("P-$keySize")

            if ($keySize -eq 256) { $sigAlgo = 'SHA256WITHECDSA' }
            elseif ($keySize -eq 384) { $sigAlgo = 'SHA384WITHECDSA' }
            elseif ($keySize -eq 521) { $sigAlgo = 'SHA512WITHECDSA' }

            $ecGen = New-Object Org.BouncyCastle.Crypto.Generators.ECKeyPairGenerator
            $genParam = New-Object Org.BouncyCastle.Crypto.Parameters.ECKeyGenerationParameters -ArgumentList $curveOid,$sRandom
            $ecGen.Init($genParam)
            $keyPair = $ecGen.GenerateKeyPair()

        } else {

            Write-Verbose "Creating BC RSA keypair of type $KeyLength"
            $isRSA = $true
            $keySize = [int]$KeyLength
            $sigAlgo = 'SHA256WITHRSA'

            $rsaGen = New-Object Org.BouncyCastle.Crypto.Generators.RsaKeyPairGenerator
            $genParam = New-Object Org.BouncyCastle.Crypto.KeyGenerationParameters -ArgumentList $sRandom,$keySize
            $rsaGen.Init($genParam)
            $keyPair = $rsaGen.GenerateKeyPair()

        }

        # export the key to a file
        Export-Pem $keyPair (Join-Path $OutputFolder 'cert.key')
    }

    # create the subject
    $subject = New-Object Org.BouncyCastle.Asn1.X509.X509Name("CN=$($Domain[0])")

    # create a .NET Dictionary to hold our extensions because that's what BouncyCastle needs
    $extDict = New-Object 'Collections.Generic.Dictionary[Org.BouncyCastle.Asn1.DerObjectIdentifier,Org.BouncyCastle.Asn1.X509.X509Extension]'

    # create the extensions we care about
    $basicConstraints = New-Object Org.BouncyCastle.Asn1.X509.X509Extension($false, (New-Object Org.BouncyCastle.Asn1.DerOctetString(New-Object Org.BouncyCastle.Asn1.X509.BasicConstraints($false))))
    $keyUsage = New-Object Org.BouncyCastle.Asn1.X509.X509Extension($true, (New-Object Org.BouncyCastle.Asn1.DerOctetString(New-Object Org.BouncyCastle.Asn1.X509.KeyUsage([Org.BouncyCastle.Asn1.X509.KeyUsage]::DigitalSignature -bor [Org.BouncyCastle.Asn1.X509.KeyUsage]::KeyEncipherment))))
    $extKeyUsage = New-Object Org.BouncyCastle.Asn1.X509.X509Extension($false, (New-Object Org.BouncyCastle.Asn1.DerOctetString(New-Object Org.BouncyCastle.Asn1.X509.ExtendedKeyUsage([Org.BouncyCastle.Asn1.X509.KeyPurposeID]::IdKPServerAuth, [Org.BouncyCastle.Asn1.X509.KeyPurposeID]::IdKPClientAuth))))
    $genNames = @()
    foreach ($name in $Domain) { $genNames += New-Object Org.BouncyCastle.Asn1.X509.GeneralName([Org.BouncyCastle.Asn1.X509.GeneralName]::DnsName, $name) }
    $sans = New-Object Org.BouncyCastle.Asn1.X509.X509Extension($false, (New-Object Org.BouncyCastle.Asn1.DerOctetString(New-Object Org.BouncyCastle.Asn1.X509.GeneralNames(@(,$genNames)))))
    $ski = New-Object Org.BouncyCastle.Asn1.X509.X509Extension($false, (New-Object Org.BouncyCastle.Asn1.DerOctetString(New-Object Org.BouncyCastle.X509.Extension.SubjectKeyIdentifierStructure($keyPair.Public))))

    # add them to a DerSet object
    $extDict.Add([Org.BouncyCastle.Asn1.X509.X509Extensions]::BasicConstraints, $basicConstraints)
    $extDict.Add([Org.BouncyCastle.Asn1.X509.X509Extensions]::KeyUsage, $keyUsage)
    $extDict.Add([Org.BouncyCastle.Asn1.X509.X509Extensions]::ExtendedKeyUsage, $extKeyUsage)
    $extDict.Add([Org.BouncyCastle.Asn1.X509.X509Extensions]::SubjectAlternativeName, $sans)
    $extDict.Add([Org.BouncyCastle.Asn1.X509.X509Extensions]::SubjectKeyIdentifier, $ski)

    # add OCSP Must Staple if requested
    if ($OCSPMustStaple) {
        Write-Verbose "Adding OCSP Must-Staple"
        $mustStaple = New-Object Org.BouncyCastle.Asn1.X509.X509Extension($false, (New-Object Org.BouncyCastle.Asn1.DerOctetString(@(,[byte[]](0x30,0x03,0x02,0x01,0x05)))))
        $extDict.Add((New-Object DerObjectIdentifier('1.3.6.1.5.5.7.1.24')), $mustStaple)
    }

    # build the extensions DerSet
    $extensions = New-Object Org.BouncyCastle.Asn1.X509.X509Extensions($extDict)
    $extDerSet = New-Object Org.BouncyCastle.Asn1.DerSet(New-Object Org.BouncyCastle.Asn1.Pkcs.AttributePkcs([Org.BouncyCastle.Asn1.Pkcs.PkcsObjectIdentifiers]::Pkcs9AtExtensionRequest,(New-Object Org.BouncyCastle.Asn1.DerSet($extensions))))

    # create the request object
    $req = New-Object Org.BouncyCastle.Pkcs.Pkcs10CertificationRequest($sigAlgo,$subject,$keyPair.Public,$extDerSet,$keyPair.Private)

    # export the csr to a file
    Export-Pem $req (Join-Path $OutputFolder 'request.csr')

    # return the raw Base64 encoded version
    return (ConvertTo-Base64Url $req.GetEncoded())
}