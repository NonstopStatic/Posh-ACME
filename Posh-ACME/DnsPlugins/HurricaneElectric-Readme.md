# How to use the Hurricane Electric DNS Plugin

This plugin works against the [Hurricane Electric DNS](https://dns.he.net/) service. It is assumed that you have already setup an account and created the DNS zone(s) you will be working against.

The Hurricane Electric DNS service does not have an API endpoint to control DNS zones. This plugin works against the web site in a similar manner to the [acme.sh](https://github.com/Neilpang/acme.sh) dns_he.sh dnsapi script.

## Using the Plugin

The plugin requires the user name and password for the Hurrican Electric DNS site. (Since user name and password will provide full control of the configured dns zones, it may be advisable to only use the account to control a domain is pointed to via CNAMEs.)

```powershell
# Using a string for the password
$HE = @{
  HEUsername = 'Userxxxxxxxxxxxxxxxx'
  HEPassword = 'PWxxxxxxxxxxxxxxxx'
}
# Using a SecureString
$HE = @{
  HEUsername = 'Userxxxxxxxxxxxxxxxx'
  HESecret = (ConvertTo-SecureString 'PWxxxxxxxxxxxxxxxx' -AsPlainText -Force)
}
# Using a PSCredential Object
$HE = @{
  HECredential=[Management.Automation.PSCredential]::new(
    'Userxxxxxxxxxxxxxxxx',
    (ConvertTo-SecureString 'PWxxxxxxxxxxxxxxxx' -AsPlainText -Force)
  )
}

# Creating a certificate using one of the PluginArgs variants.
New-PACertificate test.example.com -DnsPlugin HurricaneElectric -PluginArgs $HE
```
