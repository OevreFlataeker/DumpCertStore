using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace DumpCertstores
{
    class Program
    {
        static void Main(string[] args)
        {
            foreach (StoreLocation storeLocation in (StoreLocation[])
                Enum.GetValues(typeof(StoreLocation)))
            {
                foreach (StoreName storeName in (StoreName[])
                    Enum.GetValues(typeof(StoreName)))
                {
                    X509Store store = new X509Store(storeName, storeLocation);

                    try
                    {
                        store.Open(OpenFlags.OpenExistingOnly);

                        foreach (X509Certificate2 c in store.Certificates)
                        {
                            string email = String.Empty;
                            foreach (X509Extension extension in c.Extensions)
                            {
                                // Create an AsnEncodedData object using the extensions information.
                                AsnEncodedData asndata = new AsnEncodedData(extension.Oid, extension.RawData);
                                // Console.WriteLine("Extension type: {0}", extension.Oid.FriendlyName);
                                // Console.WriteLine("Oid value: {0}", asndata.Oid.Value);
                                if (asndata.Oid.Value == "2.5.29.17")
                                {
                                    //email = Encoding.UTF8.GetString(asndata.RawData);
                                    email = asndata.Format(false);                                    
                                    if (email.Contains("RFC822"))
                                    {
                                        email = email.Split('=')[1];
                                    }
                                    break;
                                }
                                // Console.WriteLine("Raw data length: {0} {1}", asndata.RawData.Length, Environment.NewLine);
                                // Console.WriteLine(asndata.Format(true));
                            }

                            Console.WriteLine("{0}/{1}: \"{2}\", Serial: {3}, {4} (Has Private: {5}), valid after: {6}, valid until: {7}, Issuer: \"{8}\", Thumbprint: {9}",
                                store.Location, store.Name, c.Subject, c.SerialNumber, email, c.HasPrivateKey ? "Yes" : "No", c.NotBefore, c.NotAfter, c.Issuer, c.Thumbprint, c);
                            
                        }
                         
                    }
                    catch (CryptographicException)
                    {
                        Console.WriteLine("No           {0}, {1}",
                            store.Name, store.Location);
                    }
                }
                Console.WriteLine();
            }
        }
    }
}
