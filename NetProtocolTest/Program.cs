using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace NetProtocolTest
{

    class Program
    {
        enum Protocol { DNS, UNKNOWN };

        static void Main(string[] args)
        {
            Protocol protocolToTest = Protocol.UNKNOWN;
            do
            {
                DisplayMenu();
                protocolToTest = ReadTheSelectProtocol();
            } while (protocolToTest == Protocol.UNKNOWN);
            
            ExecuteTest(protocolToTest);
        }

        private static void DisplayMenu()
        {
            string menuContent =
                "Space's internet protocol test tool\n" +
                "Select the protocol to test \n  " +
                "1.    DNS \n" +
               "Enter the number: "
                ;
            Console.Write(menuContent);
        }

        private static Protocol ReadTheSelectProtocol()
        { 
            int index = Console.Read() - '0';
            Protocol result = Protocol.UNKNOWN;
            switch (index)
            { 
                case 1:
                    result = Protocol.DNS;
                    break;
            }
            return result;
        }

        private static void ExecuteTest(Protocol protocolToTest)
        {
            ProtocolTester tester = null;
            switch (protocolToTest)
            {
                case Protocol.DNS:
                    tester = new DnsTester();
                    break;
            }

            if (tester != null)
                tester.StartTesting();

        }
    }
}
