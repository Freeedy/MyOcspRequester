using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Ocsp;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;
using X509Extension = Org.BouncyCastle.Asn1.X509.X509Extension;

namespace MyOcspRequester
{
    public enum CertificateStatusEnum { Good = 0, Revoked = 1, Unknown = 2 };
   public class MyOcspClient
    {


        protected static Asn1Object GetExtensionValue(X509Certificate cert,
              string oid)
        {
            if (cert == null)
            {
                return null;
            }

            byte[] bytes = cert.GetExtensionValue(new DerObjectIdentifier(oid)).GetOctets();

            if (bytes == null)
            {
                return null;
            }

            Asn1InputStream aIn = new Asn1InputStream(bytes);

            return aIn.ReadObject();
        }

        public List<string> GetAuthorityInformationAccessOcspUrlx5092(X509Certificate2 cert)
        {
            return GetAuthorityInformationAccessOcspUrl(cert.ConvertToBCX509Certificate());
        }
        public  List<string> GetAuthorityInformationAccessOcspUrl(X509Certificate cert)
        {
            List<string> ocspUrls = new List<string>();

            try
            {
                Asn1Object obj = GetExtensionValue(cert, X509Extensions.AuthorityInfoAccess.Id);

                if (obj == null)
                {
                    return null;
                }
                Asn1Sequence s = (Asn1Sequence)obj;
                IEnumerator elements = s.GetEnumerator();

                while (elements.MoveNext())
                {
                    Asn1Sequence element = (Asn1Sequence)elements.Current;
                    DerObjectIdentifier oid = (DerObjectIdentifier)element[0];

                    if (oid.Id.Equals("1.3.6.1.5.5.7.48.1")) // Is Ocsp?
                    {
                        Asn1TaggedObject taggedObject = (Asn1TaggedObject)element[1];
                        GeneralName gn = (GeneralName)GeneralName.GetInstance(taggedObject);
                        ocspUrls.Add(((DerIA5String)DerIA5String.GetInstance(gn.Name)).GetString());
                    }
                }
            }
            catch (Exception e)
            {
                throw new Exception("Error parsing AIA.", e);
            }

            return ocspUrls;
        }



        /// <summary>
        /// Online Verify  Certificate Status
        /// </summary>
        /// <param name="certificate"></param>
        /// <returns></returns>
        public CertificateStatusEnum ValidateOCSPx509_2(X509Certificate2 certificate)
        {
            X509Certificate2 issuer = GetIssuerCertificate(certificate);

            return ValidateOCSPx509_2(certificate, issuer);
        }

        public CertificateStatusEnum ValidateOCSPx509_2(X509Certificate2 cert, X509Certificate2 cacert)
        {
            return ValidateOCSP(cert.ConvertToBCX509Certificate(), cacert.ConvertToBCX509Certificate());
        }



        public CertificateStatusEnum ValidateOCSP(X509Certificate cert, X509Certificate cacert)
        {
            List<string> urls = GetAuthorityInformationAccessOcspUrl(cert);
            if (urls.Count == 0)
            {
                throw new Exception("No OCSP url found in ee certificate.");
            }

            string url = urls[0];
            Console.WriteLine("Sending to :  '" + url + "'...");

            byte[] packtosend = CreateOCSPPackage(cert, cacert);

            byte[] response = PostRequest(url, packtosend, "Content-Type", "application/ocsp-request");

            return VerifyResponse(response);
        }

        public byte[] ToByteArray(Stream stream)
        {
            byte[] buffer = new byte[4096 * 8];
            MemoryStream ms = new MemoryStream();

            int read = 0;

            while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
            {
                ms.Write(buffer, 0, read);
            }

            return ms.ToArray();
        }

        public byte[] PostRequest(string url, byte[] data, string contentType, string accept)
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = "POST";
            request.ContentType = contentType;
            request.ContentLength = data.Length;
            request.Accept = accept;
            Stream stream = request.GetRequestStream();
            stream.Write(data, 0, data.Length);
            stream.Close();
            HttpWebResponse response = (HttpWebResponse)request.GetResponse();
            Stream respStream = response.GetResponseStream();
            Console.WriteLine(string.Format("HttpStatusCode : {0}", response.StatusCode.ToString()));
            byte[] resp = ToByteArray(respStream);
            respStream.Close();

            return resp;
        }

        private CertificateStatusEnum VerifyResponse(byte[] response)
        {
            OcspResp r = new OcspResp(response);
            CertificateStatusEnum cStatusEnum = CertificateStatusEnum.Unknown;
            switch (r.Status)
            {
                case OcspRespStatus.Successful:
                    BasicOcspResp or = (BasicOcspResp)r.GetResponseObject();

                    //ValidateResponse(or, issuerCert);
                    Console.WriteLine(or.Responses.Length);
                    if (or.Responses.Length == 1)
                    {
                        SingleResp resp = or.Responses[0];


                        // ValidateCertificateId(issuerCert, eeCert, resp.GetCertID());
                        //ValidateThisUpdate(resp);
                        //ValidateNextUpdate(resp);

                        Object certificateStatus = resp.GetCertStatus();

                        if (certificateStatus == null)
                        {
                            Console.WriteLine("Status is null ! ");
                        }
                        if (certificateStatus == null || certificateStatus == Org.BouncyCastle.Ocsp.CertificateStatus.Good)
                        {
                            cStatusEnum = CertificateStatusEnum.Good;
                            Console.WriteLine("Status is GOOD ! ");
                        }
                        else if (certificateStatus is Org.BouncyCastle.Ocsp.RevokedStatus)
                        {
                            cStatusEnum = CertificateStatusEnum.Revoked;
                            Console.WriteLine("Status is Revoked ! ");
                        }
                        else if (certificateStatus is Org.BouncyCastle.Ocsp.UnknownStatus)
                        {
                            cStatusEnum = CertificateStatusEnum.Unknown;
                            Console.WriteLine("Status is Unknown ! ");
                        }
                    }
                    break;
                default:
                    throw new Exception("Unknow status '" + r.Status + "'.");
            }

            return cStatusEnum;
        }


        private static byte[] CreateOCSPPackage(X509Certificate cert, X509Certificate cacert)
        {
            OcspReqGenerator gen = new OcspReqGenerator();
            try
            {
                CertificateID certId = new CertificateID(CertificateID.HashSha1, cacert, cert.SerialNumber);

                gen.AddRequest(certId);
                gen.SetRequestExtensions(CreateExtension());
                OcspReq req;
                req = gen.Generate();
                return req.GetEncoded();
            }
            catch (OcspException e)
            {
                Console.WriteLine(e.StackTrace);
            }
            catch (IOException e)
            {

                Console.WriteLine(e.StackTrace);
            }
            return null;


        }

        private static X509Extensions CreateExtension()
        {
            byte[] nonce = new byte[16];
            Hashtable exts = new Hashtable();

            BigInteger nc = BigInteger.ValueOf(DateTime.Now.Ticks);
            X509Extension nonceext = new X509Extension(false, new DerOctetString(nc.ToByteArray()));


            exts.Add(OcspObjectIdentifiers.PkixOcspNonce, nonceext);
            return new X509Extensions(exts);

        }


        public X509Certificate2 GetIssuerCertificate(X509Certificate2 cert)
        {
            if (cert.Subject == cert.Issuer) { return cert; } //Self Signed Certificate
            X509Chain chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.Build(cert);
            X509Certificate2 issuer = null;
            if (chain.ChainElements.Count > 1)
            {
                issuer = chain.ChainElements[1].Certificate;
            }
            chain.Reset();
            return issuer;
        }

    }
}
