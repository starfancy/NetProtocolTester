using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Diagnostics;

namespace NetProtocolTest
{
    abstract class ProtocolTester
    {
        //abstract  public void DisplayInfo();
        //abstract public string ReadOption();
        //abstract public void ExecuteTest();
        //abstract public void DisplayResult();
        abstract public void StartTesting();
    }

    struct DnsDiagramHead
    {
        public Int16 id;
        public Int16 flag;
        public Int16 queryNum;
        public Int16 resRecNum;
        public Int16 autResRecNum;
        public Int16 extResRecNum;

        public int DiagramSize
        {
            get
            {
                return 6 * sizeof(UInt16);
            }
        }

        public byte[] ToByteArray()
        {
            byte[] buffer = new byte[DiagramSize];
            int index = 0;
            BitConverter.GetBytes(IPAddress.HostToNetworkOrder(id)).CopyTo(buffer, index);
            index += sizeof(Int16);
            BitConverter.GetBytes(IPAddress.HostToNetworkOrder(flag)).CopyTo(buffer, index);
            index += sizeof(Int16);
            BitConverter.GetBytes(IPAddress.HostToNetworkOrder(queryNum)).CopyTo(buffer, index);
            index += sizeof(Int16);
            BitConverter.GetBytes(IPAddress.HostToNetworkOrder(resRecNum)).CopyTo(buffer, index);
            index += sizeof(Int16);
            BitConverter.GetBytes(IPAddress.HostToNetworkOrder(autResRecNum)).CopyTo(buffer, index);
            index += sizeof(Int16);
            BitConverter.GetBytes(IPAddress.HostToNetworkOrder(extResRecNum)).CopyTo(buffer, index);
            return buffer;
        }
    }

    
    class DnsHeadFlag
    {
        public const Int16 QRquery = 0;
        public const Int16 QRresponse = unchecked((Int16)(1 << 15));
        public const Int16 Opcode = 0;
        public const Int16 AA = 1 << 10;
        public const Int16 TC = 1 << 9;
        public const Int16 RD = 1 << 8;
        public const Int16 RA = 1 << 7;
    }

    class DnsResourceRecordType
    {
        public const Int16 A = 1;  //a host address
        public const Int16 NS = 2; // an authoritative name server
        public const Int16 MD = 3; // a mail destination(Obsolete - use MX)
        public const Int16 MF = 4; // a mail forwarder(Obsolete - use MX)
        public const Int16 CNAME = 5; // the canonical name for an alias
        public const Int16 SOA = 6; // marks the start of a zone of authority
        public const Int16 MB = 7;  //a mailbox domain name(EXPERIMENTAL)
        public const Int16 MG = 8; // a mail group member(EXPERIMENTAL)
        public const Int16 MR = 9; //a mail rename domain name(EXPERIMENTAL)
        public const Int16 NULL = 10; // a null RR(EXPERIMENTAL)
        public const Int16 WKS = 11; // a well known service description
        public const Int16 PTR = 12; //a domain name pointer
        public const Int16 HINFO = 13; // host information
        public const Int16 MINFO = 14; // mailbox or mail list information
        public const Int16 MX = 15; // mail exchange
        public const Int16 TXT = 16; // text strings
    }



    struct DnsQueryBody
    {
        public byte[] queryName;
        public Int16 queryType;
        public Int16 queryClass;

        public int DiagramSize
        {
            get { return queryName.Length* sizeof(byte)
                + 2*sizeof(Int16);}
        }

        public byte[] ToByteArray()
        {
            byte[] buffer = new byte[DiagramSize];
            int index = 0;
            queryName.CopyTo(buffer, index);
            index += queryName.Length;
            BitConverter.GetBytes(IPAddress.HostToNetworkOrder(queryType)).CopyTo(buffer, index);
            index += sizeof(Int16);
            BitConverter.GetBytes(IPAddress.HostToNetworkOrder(queryClass)).CopyTo(buffer, index);
            index += sizeof(Int16);
            return buffer;
        }

        public string GetQueryNameString()
        {
            char[] nameBuf = new Char[queryName.Length];
            int secCount=0;
            for (int i = 0; i < nameBuf.Length; i++)
            {
                if (secCount == 0)
                {
                    secCount = queryName[i];
                    if (i == 0 || i == nameBuf.Length - 1)
                        nameBuf[i] = ' ';
                    else
                        nameBuf[i] = '.';
                }
                else
                {
                    nameBuf[i] = (char)queryName[i];
                    secCount--;
                }
            }
            string nameString = new String(nameBuf).Trim(); 
            return nameString;
        }
    }


    struct DnsResourceRecord
    {
        public byte[] domainName;
        public Int16 resType;
        public Int16 resClass;
        public Int32 ttl;
        public Int16 resLength;
        public byte[] resContent;

        public int DiagramSize
        {
            get
            {
                return domainName.Length * sizeof(byte)
                    + resContent.Length  *sizeof(byte)
                    + 3 * sizeof(UInt16) + 1*sizeof(UInt32);
            }
        }

        public byte[] ToByteArray()
        {
            byte[] buffer = new byte[DiagramSize];
            int index = 0;
            domainName.CopyTo(buffer, index);
            index += domainName.Length;
            BitConverter.GetBytes(IPAddress.HostToNetworkOrder(resType)).CopyTo(buffer, index);
            index += sizeof(Int16);
            BitConverter.GetBytes(IPAddress.HostToNetworkOrder(resClass)).CopyTo(buffer, index);
            index += sizeof(Int16);
            BitConverter.GetBytes(IPAddress.HostToNetworkOrder(ttl)).CopyTo(buffer, index);
            index += sizeof(Int32);
            BitConverter.GetBytes(IPAddress.HostToNetworkOrder(resLength)).CopyTo(buffer, index);
            index += sizeof(Int16);
            resContent.CopyTo(buffer, index);
            return buffer;
        }

        public string GetResourceContentString()
        {
            Debug.Assert(resLength > 0);
            char[] contentBuf = null;
            string contentString = null;
            switch (resType)
            {
                case DnsResourceRecordType.A:
                    contentString = resContent[0].ToString() + '.' +
                        resContent[1].ToString() + '.' +
                        resContent[2].ToString() + '.' +
                        resContent[3].ToString();
                    break;
                case DnsResourceRecordType.CNAME:
                    contentBuf = new Char[resLength];
                    int secCount = 0;
                    for (int i = 0; i < contentBuf.Length; i++)
                    {
                        if (secCount == 0)
                        {
                            secCount = resContent[i];
                            if (i == 0 || i == contentBuf.Length - 1)
                                contentBuf[i] = ' ';
                            else
                                contentBuf[i] = '.';
                        }
                        else
                        {
                            contentBuf[i] = (char)resContent[i];
                            secCount--;
                        }
                        Debug.Assert(contentBuf != null);
                        contentString = new string(contentBuf).Trim();
                    }
                    break;
                default:
                    contentString = "Unknown resource record.";
                    break;
            }
            return contentString;
        }
    }
    

    class DnsTester :  ProtocolTester
    {
        protected IPEndPoint dnsServerEndPoint;
        private string targetHostName;
        private const int DnsServerPort = 53;
        private const Int16 DnsDiagramID = (Int16)12345;

        public DnsTester()
        { 
            
        }

        public void ExecuteTest()
        {
            Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            byte[] buffer = PrepareDnsQuery();
            socket.SendTo(buffer, dnsServerEndPoint);
            // Receive the response from the server
            byte[] dnsData = new byte[1000];
            EndPoint endPoint = (EndPoint)dnsServerEndPoint;
            socket.ReceiveFrom(dnsData, ref endPoint);

            int index = 0, count=0;
            DnsDiagramHead diagramHead = ParseResponseDiagramHead(dnsData, index, ref count);
            index += count;
#region ErrorHandling
            if (diagramHead.resRecNum == 0)
            {
                Console.WriteLine("Could not resolve the host name.");
                return;
            }
            // rcode nonzero means error is found
            if ((diagramHead.flag & 0x08) != 0)
            {
                Console.WriteLine("Dns Error! rcode =%d", (diagramHead.flag & 0x08));
                return;
            }
#endregion 
            // Make sure queryNum=1
            Debug.Assert(diagramHead.queryNum == 1);
            DnsQueryBody queryBody = ParseDnsQueryBody(dnsData, index, ref count);
            index += count;
            Console.WriteLine("Dns Query Name:  "+queryBody.GetQueryNameString());

            int resRecordCount=diagramHead.resRecNum;
            DnsResourceRecord[] resourceRecords = new DnsResourceRecord[resRecordCount];
            for (int i = 0; i < resRecordCount; i++)
            {
                resourceRecords[i] = ParseDnsResourceRecord(dnsData, index, ref count);
                index += count;
            }

            foreach (DnsResourceRecord record in resourceRecords)
                Console.WriteLine("Result is " + record.GetResourceContentString());
            
            Console.WriteLine("\nPress any  key to exit.");
            Console.ReadKey();
        }

        public override void StartTesting()
        {
            GetTheTestInfo();
            ExecuteTest();
        }

        public  void GetTheTestInfo()
        {
            string info;
            info =
                "Enter the ip address of  the dns server:  "
             ;
            Console.Write(info);
            Console.ReadLine();
            string ipAddress = Console.ReadLine();
            dnsServerEndPoint = new IPEndPoint( IPAddress.Parse(ipAddress), DnsServerPort);
            Console.WriteLine("");

            info =
                "Enter the target web name to resolve:  "
            ;
            Console.Write(info);
            targetHostName = Console.ReadLine();
            // check if the host name ends with '.'
            if (targetHostName[targetHostName.Length - 1] != '.')
                targetHostName = targetHostName.Insert(targetHostName.Length, ".");
        }

        byte[] PrepareDnsQuery()
        {
            // prepare the head
            DnsDiagramHead diagramHead = new DnsDiagramHead();
            diagramHead.id = DnsDiagramID;
            diagramHead.flag = 0;
            diagramHead.flag |= DnsHeadFlag.QRquery | DnsHeadFlag.RD | DnsHeadFlag.TC;
            diagramHead.queryNum = 1;

            // prepare the body
            DnsQueryBody queryBody;
            queryBody.queryName = new byte[targetHostName.Length + 1];

            for (int i = 0, j = -1; i < targetHostName.Length; i++)
            {
                if (targetHostName[i] == '.')
                {
                    // j contains the the previous index value of  '.' in queryName
                    queryBody.queryName[j + 1] = (byte)(i - j - 1);
                    j = i;
                }
                else
                {
                    queryBody.queryName[i + 1] = (byte)targetHostName[i];
                }
            }
            queryBody.queryName[targetHostName.Length] = 0;

            queryBody.queryType = 1; // 'A' address
            queryBody.queryClass = 1; // IP address

            int bufferSize = diagramHead.DiagramSize + queryBody.DiagramSize;
            byte[] buffer = new byte[bufferSize];
            int index = 0;
            diagramHead.ToByteArray().CopyTo(buffer, index);
            index += diagramHead.DiagramSize;
            queryBody.ToByteArray().CopyTo(buffer, index);
            index+= queryBody.DiagramSize;

            return buffer;
        }

        DnsDiagramHead ParseResponseDiagramHead(byte[] buffer, int beginIndex, ref int parseCount)
        {
            DnsDiagramHead diagramHead = new DnsDiagramHead();
            int index = beginIndex;
            diagramHead.id =  IPAddress.NetworkToHostOrder(BitConverter.ToInt16(buffer, index));
            index += sizeof(Int16);
            diagramHead.flag = IPAddress.NetworkToHostOrder(BitConverter.ToInt16(buffer, index));
            index += sizeof(Int16);
            diagramHead.queryNum = IPAddress.NetworkToHostOrder(BitConverter.ToInt16(buffer, index));
            index += sizeof(Int16);
            diagramHead.resRecNum = IPAddress.NetworkToHostOrder(BitConverter.ToInt16(buffer, index));
            index += sizeof(Int16);
            diagramHead.autResRecNum = IPAddress.NetworkToHostOrder(BitConverter.ToInt16(buffer, index));
            index += sizeof(Int16);
            diagramHead.extResRecNum = IPAddress.NetworkToHostOrder(BitConverter.ToInt16(buffer, index));
            index += sizeof(Int16);
            parseCount = index - beginIndex;
            return diagramHead;
        }

        DnsQueryBody ParseDnsQueryBody(byte[] buffer, int beginIndex, ref int parseCount)
        {
            DnsQueryBody queryBody = new DnsQueryBody();
            // get the length of the query name
            int nameLength = 0;
            int sectionLen, index = beginIndex;
            while ((sectionLen = buffer[index]) != 0)
            {
                nameLength += sectionLen + 1;
                index += sectionLen + 1;
            }
            nameLength += 1; // add the count of the last '0'
            index++;

            byte[] nameBuffer = new byte[nameLength];
            Array.Copy(buffer, beginIndex, nameBuffer, 0, nameLength);
            queryBody.queryName = nameBuffer;

            queryBody.queryType = IPAddress.NetworkToHostOrder(BitConverter.ToInt16(buffer, index));
            index+= sizeof(Int16);
            queryBody.queryClass = IPAddress.NetworkToHostOrder(BitConverter.ToInt16(buffer, index));
            index += sizeof(Int16);
            parseCount = index - beginIndex;
            return queryBody;
        }

        DnsResourceRecord ParseDnsResourceRecord(byte[] buffer, int beginIndex, ref int parseCount)
        {
            DnsResourceRecord resourceRecord = new DnsResourceRecord();
            int index = beginIndex;
            byte nameFlag = buffer[index];
            if ((nameFlag & 0xc0) == 0xc0) // check if the domain name is a 16-bit pointer;
            {
                resourceRecord.domainName = new Byte[sizeof(Int16)];
                Array.Copy(buffer, index, resourceRecord.domainName, 0, sizeof(Int16));
                index += sizeof(Int16);
            }
            else // reach here means it is a domain name string
            {
                // get the length of the query name
                int nameLength = 0;
                int sectionLen;
                index = beginIndex;
                while ((sectionLen = buffer[index]) != 0)
                {
                    nameLength += sectionLen + 1;
                    index += sectionLen + 1;
                }
                nameLength += 1; // add the count of the last '0'
                index++;
                resourceRecord.domainName = new byte[nameLength];
                Array.Copy(buffer, index, resourceRecord.domainName, 0, nameLength);
            }
            resourceRecord.resType = IPAddress.NetworkToHostOrder(BitConverter.ToInt16(buffer, index));
            index += sizeof(Int16);
            resourceRecord.resClass = IPAddress.NetworkToHostOrder(BitConverter.ToInt16(buffer, index));
            index += sizeof(Int16);
            resourceRecord.ttl = IPAddress.NetworkToHostOrder(BitConverter.ToInt32(buffer, index));
            index += sizeof(Int32);
            resourceRecord.resLength = IPAddress.NetworkToHostOrder(BitConverter.ToInt16(buffer, index));
            index += sizeof(Int16);
            resourceRecord.resContent = new Byte[resourceRecord.resLength];
            Array.Copy(buffer, index, resourceRecord.resContent, 0, resourceRecord.resLength);
            index += resourceRecord.resLength;
            parseCount = index - beginIndex;
            return resourceRecord;
        }

    }
}
