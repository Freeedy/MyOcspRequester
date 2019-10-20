using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.X509;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace MyOcspRequester
{
   public static  class Helper
    {

       public static X509Certificate ConvertToBCX509Certificate(this X509Certificate2 cert)
       {

           X509CertificateParser parser = new X509CertificateParser();
           byte[] certarr = cert.Export(X509ContentType.Cert);
           return parser.ReadCertificate(certarr);

       }
    }
}
