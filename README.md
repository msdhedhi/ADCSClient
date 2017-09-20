# ADCSClient
This is a java library to sign the certificate signing requests ( i.e. CSR ) using Windows 2012 Active Directory Certificate services ( i.e. ADCS ).

If you plan to use this library, then make sure to first visit https://blogs.technet.microsoft.com/askds/2010/05/25/enabling-cep-and-ces-for-enrolling-non-domain-joined-computers-for-certificates/ to learn more about what services need to be installed on the ADCS server in order to use the ADCS web services from a system which is not part of the domain.

In the code I have provided, I am generating a CSR and then calling the windows ADCS web service to sign it. The generation of CSR can be skipped if you already have a CSR. If you already have a CSR then make sure it uses the extension "1.3.6.1.4.1.311.20.2" to specify the ADCS Template to use. Also, depending on how the administrator has setup the template in ADCS, it may or may not overwrite the subject you specify in the CSR when signing the certificate.

## Background
I was working on a project where there was a requirement to sign the CSRs using a windows server. The client calling the ADCS web service will be running on a Linux based server. I did some online lookups and could only find sample code writing in C# using windows libraries. I used one of the sample codes and captured the request/responses using a tool called fiddler ( http://www.telerik.com/fiddler ). Once I had the captured requests/responses, I was able to write this java code and replicate what the windows libraries are doing.

## WARNING
Please note that I have only tested this with a Windows 2012 server. It may or may not work with other versions of windows server.
