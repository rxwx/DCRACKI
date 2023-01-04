# DCRACKI

Messing about with DPAPI MasterKeys using SharpDPAPI.

Currently supports:

* Dumping MasterKey hashes in JtR/Hashcat format
* Testing a single password against a MasterKey file
* Pass-the-Hash (NTLM or SHA1, depending on Domain context)
* Testing multiple passwords/hashes against a single MasterKey hash
* Parsing the `Preferred` file to get the preferred MasterKey GUID
 
