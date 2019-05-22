using System;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace ClientCertificateRequests
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Make sure you run this as administator. Otherwise you won't have access to the private key to sign the request.");
            Console.WriteLine("If you call this exe with args, they mean the following:");
            Console.WriteLine("     arg0 - Thumbprint of the cert to encript call with;");
            Console.WriteLine("     arg1 - The URL to call with the ClientCert utils");
            string thumbprint = null;
            Uri url = null;

            if (args.Length >= 1)
            {
                thumbprint = args[0];

                if (args.Length == 2)
                {
                    url = new Uri(args[1]);
                }
                else
                {
                    Console.Error.WriteLine("At most 2 arguments are supporrted");
                    return;
                }
            }

            if (string.IsNullOrEmpty(thumbprint))
            {
                Console.Write("Enter thumbprint of the Client Cert: ");
                do
                {
                    thumbprint = Console.ReadLine();
                    if (string.IsNullOrEmpty(thumbprint))
                    {
                        Console.WriteLine("You have to specify a non-empty thumbprint to continue");
                    }
                } while (string.IsNullOrEmpty(thumbprint));
            }

            if (url == null)
             {
                Console.Write("Enter url to make cert signed request to: ");
                do
                {
                    try
                    {
                        url = new Uri(Console.ReadLine());
                    }
                    catch
                    {
                        Console.Write("Failed to parse the url you entered. Try adding the url again:");
                    }
                }
                while (url == null);
            }

            MakeCertSignedRequests(thumbprint, url).ConfigureAwait(false).GetAwaiter().GetResult();
        }

        private static async Task MakeCertSignedRequests(string thumbprint, Uri uri)
        {
            var cert = FindCertificateByThumbprint(thumbprint, StoreName.My, StoreLocation.LocalMachine);

            try
            {
                var response = await SendRequest(cert, uri);
                Console.WriteLine($"Response Code: {response.StatusCode} , Message: {response.Content.ToString()}");
            }
            catch (Exception e)
            {
                Console.Error.WriteLine($"Failed to make the request with exception: {e.ToString()}");
            }
        }

        private static async Task<HttpResponseMessage> SendRequest(X509Certificate2 clientCert, Uri requestUri)
        {
            using (var httpHandler = new HttpClientHandler())
            {
                httpHandler.ServerCertificateCustomValidationCallback = (message, certificate, chain, sslErrors) =>
                {
                    // Allow valid Ssl connections
                    if (sslErrors == SslPolicyErrors.None || (sslErrors & ~SslPolicyErrors.RemoteCertificateNameMismatch) == SslPolicyErrors.None)
                    {
                        return true;
                    }

                    return false;
                };

                httpHandler.ClientCertificateOptions = ClientCertificateOption.Manual;
                httpHandler.ClientCertificates.Add(clientCert);

                using (var client = new HttpClient(httpHandler))
                {
                    return await client.GetAsync(requestUri);
                }
            }
        }

        private static X509Certificate2 FindCertificateByThumbprint(string thumbprint, StoreName storeName, StoreLocation storeLocation)
        {
            using (var store = new X509Store(storeName, storeLocation))
            {
                store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly);

                var certs = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: true);

                if (certs.Count == 0)
                {
                    Console.WriteLine("Certificate does not exist in the store provided");
                    throw new Exception("Inexistent certificate");
                }
                else if (certs.Count == 1)
                {
                    return certs[0];
                }
                else
                {
                    throw new Exception("You have multiple certificates with the same thumbprint!!");
                }
            }
        }
    }
}
