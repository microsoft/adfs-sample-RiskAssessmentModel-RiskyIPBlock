using Microsoft.IdentityServer.Public.ThreatDetectionFramework;
using Microsoft.VisualBasic.FileIO;
using System;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;
using Microsoft.IdentityServer.Public;

namespace ThreatDetectionModule
{
    /// <summary>
    /// UserRiskAnalyzer is the main class implementing ThreatDetectionModule abstract class and IRequestReceivedThreatDetectionModule interface.
    /// During registration of the module with ADFS, pass a config file with Banned IPs seperated with ";" or ","
    /// This module will compare the IP of the authentication requests with the IPs from that file
    /// If a match is found, method returns Throttelstatus as 2 (Block), else it returns 1 (Allow).
    /// </summary>
    public class UserRiskAnalyzer : Microsoft.IdentityServer.Public.ThreatDetectionFramework.ThreatDetectionModule, IRequestReceivedThreatDetectionModule
    {
        private HashSet<IPAddress> _blockedIPs = new HashSet<IPAddress>();

        public override string VendorName => "Microsoft";
        public override string ModuleIdentifier => "UserRiskAnalyzer";

        /// <summary>
        /// ADFS calls this method while loading the module and it passes the contents of Config file through configData
        /// This method caches the IPs from it so that it can used when authentication requests are evaluated
        /// </summary>
        /// <param name="logger"></param>
        /// <param name="configData"></param>
        public override void OnAuthenticationPipelineLoad(ThreatDetectionLogger logger, ThreatDetectionModuleConfiguration configData)
        {
            try
            {
                ReadConfigFile(logger, configData);
            }
            catch (Exception ex)
            {
                logger.WriteAdminLogErrorMessage(ex.ToString());
                throw;
            }
        }

        /// <summary>
        /// Parses the config file and store it in HashSet
        /// </summary>
        /// <param name="logger"></param>
        /// <param name="configData"></param>
        private void ReadConfigFile(ThreatDetectionLogger logger, ThreatDetectionModuleConfiguration configData)
        {
            HashSet<IPAddress> ipAddressSet = new HashSet<IPAddress>();
            TextFieldParser textFieldParser = new TextFieldParser(configData.ReadData())
            {
                TextFieldType = FieldType.Delimited
            };
            textFieldParser.SetDelimiters(";", ",");
            while (!textFieldParser.EndOfData)
            {
                string[] ipValueList = textFieldParser.ReadFields();

                if (null == ipValueList) continue;

                foreach (var ipValue in ipValueList)
                {
                    try
                    {
                        if (string.IsNullOrEmpty(ipValue))
                        {
                            continue;
                        }

                        IPAddress ipAddress = IPAddress.Parse(ipValue);
                        ipAddressSet.Add(ipAddress);
                        logger?.WriteDebugMessage($"Loaded IP {ipAddress}");
                    }
                    catch (Exception ex)
                    {
                        // Continue to load additional IPs from the configuration file.
                        logger?.WriteAdminLogErrorMessage($"Failed reading IP {ipValue} exception {ex}");
                    }
                }
            }

            _blockedIPs = ipAddressSet;
        }

        public override void OnAuthenticationPipelineUnload(ThreatDetectionLogger logger)
        {
        }

        /// <summary>
        /// ADFS calls this method when there is any change in the configuration. This typically happens when Import-AdfsThreatDetectionModuleConfiguration cmdlet is executed
        /// ADFS passes the contents of Config file through configData
        /// This method caches the IPs from it so that it can used when authentication requests are evaluated
        /// </summary>
        /// <param name="logger"></param>
        /// <param name="configData"></param>
        public override void OnConfigurationUpdate(ThreatDetectionLogger logger, ThreatDetectionModuleConfiguration configData)
        {
            ReadConfigFile(logger,configData);
        }

        /// <summary>
        /// Implements the interface method. 
        /// This method compares the IP (if from extranet) from the authentication request with all the banned IPs. If a match is found, method returns Throttelstatus as 2 (Block), else it returns 1 (Allow).
        /// </summary>
        /// <param name="logger"></param>
        /// <param name="requestContext"></param>
        /// <returns></returns>
        public Task<ThrottleStatus> EvaluateRequest(ThreatDetectionLogger logger, RequestContext requestContext)
        {
            if (requestContext.ClientLocation.HasValue && requestContext.ClientLocation.Value == NetworkLocation.Extranet)
            {
                foreach (IPAddress clientIpAddress in requestContext.ClientIpAddresses)
                {
                    logger?.WriteDebugMessage($"Block saw IP {clientIpAddress}");

                    if (this._blockedIPs.Contains(clientIpAddress))
                    {
                        logger?.WriteDebugMessage($"Blocked request from IP {clientIpAddress}");

                        return Task.FromResult<ThrottleStatus>(ThrottleStatus.Block);
                    }
                }
            }

            return Task.FromResult<ThrottleStatus>(ThrottleStatus.Allow);
        }
    }
}
