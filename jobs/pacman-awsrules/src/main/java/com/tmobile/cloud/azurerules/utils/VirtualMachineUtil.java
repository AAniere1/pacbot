package com.tmobile.cloud.azurerules.utils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.HashMultimap;
import com.google.common.collect.Maps;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.tmobile.cloud.awsrules.utils.PacmanUtils;
import com.tmobile.cloud.awsrules.utils.RulesElasticSearchRepositoryUtil;
import com.tmobile.cloud.azurerules.dto.NSGRuleDTO;
import com.tmobile.cloud.azurerules.dto.NicPublicData;
import com.tmobile.cloud.constants.PacmanRuleConstants;
import com.tmobile.pacman.commons.PacmanSdkConstants;
import com.tmobile.pacman.commons.exception.InvalidInputException;
import com.tmobile.pacman.commons.exception.RuleExecutionFailedExeption;

import com.tmobile.pacman.commons.utils.IPUtils;

/**
 * The Class VirtualMachineUtil.
 */
public class VirtualMachineUtil {
	
	private static final String BACKEND_NETWORK_INTERFACE_ID = "backendNetworkInterfaceId";
	private static final String IP_ALL = "*,any,Internet,0.0.0.0,0.0.0.0/0";
	/** The Constant logger. */
	private static final Logger logger = LoggerFactory.getLogger(VirtualMachineUtil.class);

    /**
     * @param vmJsonArray
     * @return
     */
    public static List<JsonObject> getLbDetails(JsonArray vmJsonArray){
    	List<JsonObject> loadbalancerList = new ArrayList<>();
    	if (vmJsonArray!=null && vmJsonArray.size() > 0) {
    		for (JsonElement lbData : vmJsonArray) {
    			JsonObject lbObj = lbData.getAsJsonObject();
    			loadbalancerList.add(lbObj.get(PacmanRuleConstants.SOURCE).getAsJsonObject());
			}
		}
		return loadbalancerList;
    }
    
	/**
	 * @param ruleParam
	 * @param region
	 * @param subscription
	 * @param vmNSGList
	 * @param vmNicArray
	 * @param lbCheck
	 * @return
	 * @throws Exception
	 */
	public static Map<String, Object> getVMPublicPorts(Map<String, String> ruleParam, String region,
			String subscription, JsonArray vmNSGList, JsonArray vmNicArray, boolean lbCheck)
			throws Exception {
		String esNicUrl= PacmanRuleConstants.ES_URL_NIC;
		String esNsgRuleUrl = ruleParam.get(PacmanRuleConstants.ES_NSG_URL);
		String pacmanHost = PacmanUtils.getPacmanHost(PacmanRuleConstants.ES_URI);
    	List<NicPublicData> publicNIC = new ArrayList<>();
    	List<String> publicIPs = new ArrayList<>();
		boolean isPublic = false;
		
		List<String> allowedCidrList = PacmanUtils.getAllowedCidrsFromConfigProperty(ruleParam);
		
		for(JsonElement vmNicJsonElement : vmNicArray) {
			String nic = vmNicJsonElement.getAsString();
			Map<String, Object> nicDetails = getNicDetails(pacmanHost+esNicUrl, nic);
			String subnet = (String) nicDetails.get("subnet");
			String publicIP = (String) nicDetails.get("publicIP");
			boolean hasPublicIP = (boolean) nicDetails.get("hasPublicIP");
			//for LB rule NIC need not have public IP
			if(hasPublicIP || lbCheck) {
				// sort NSG by nic
				JsonArray nsgList = getNsgByNic(vmNSGList, nic, subnet);
				
				Map<String, Set<String>> publicDetails = getPublicPortsForNic(nsgList, pacmanHost+esNsgRuleUrl, region, subscription, allowedCidrList);
				if(null!= publicDetails && !publicDetails.isEmpty()) {
					isPublic = true;
					NicPublicData nicData = new NicPublicData(nic.charAt(0) == '/' ? nic.substring(1) : nic,
							publicDetails);
					publicNIC.add(nicData);
					publicIPs.add(publicIP);
				}
				
			}
		}
    	
    	Map<String, Object> retData = new HashMap<>();
    	retData.put(PacmanRuleConstants.PUBLIC_NIC, publicNIC);
    	retData.put(PacmanRuleConstants.IS_PUBLIC, isPublic);
    	retData.put(PacmanRuleConstants.PUBLICIP, publicIPs);
    	return retData;
    }

	/**
	 * @param vmNSGList
	 * @param nic
	 * @param subnet
	 * @return
	 */
	private static JsonArray getNsgByNic(JsonArray vmNSGList, String nic, String subnet) {
		JsonArray nsgList = new JsonArray();
		for (JsonElement vmNSGJsonElement : vmNSGList) {
			JsonObject eachNSG = vmNSGJsonElement.getAsJsonObject();
			String attachedTo = eachNSG.has(PacmanRuleConstants.ATTACHED_TO)
					? eachNSG.get(PacmanRuleConstants.ATTACHED_TO).getAsString()
					: null;
			String attachedToType = eachNSG.has(PacmanRuleConstants.ATTACHED_TO_TYPE)
					? eachNSG.get(PacmanRuleConstants.ATTACHED_TO_TYPE).getAsString()
					: null;
			if (!StringUtils.isEmpty(attachedToType) && !StringUtils.isEmpty(attachedTo)) {
				if (attachedToType.equals(PacmanRuleConstants.SUBNET)) {
					String[] subnetIdArray = attachedTo.split("/");
					String subnetAttached =subnetIdArray[subnetIdArray.length-1];
					if (subnetAttached.equalsIgnoreCase(subnet)) {
						nsgList.add(vmNSGJsonElement);
					} 
				} else {
					if (attachedTo.equalsIgnoreCase(getValidAzureResourceId(nic))) {
						nsgList.add(vmNSGJsonElement);
					} 
				}
			}
		}
		return nsgList;
	}
	
	/**
	 * Gets the public ports for nic.
	 *
	 * @param nsgList the nsg list
	 * @param esNsgUrl the es nsg url
	 * @param region the region
	 * @param subscription the subscription
	 * @param publicAddress the public address
	 * @return the public ports for nic
	 * @throws Exception the exception
	 */
	public static Map<String,Set<String>> getPublicPortsForNic(JsonArray nsgList, String esNsgUrl, String region,
			String subscription, List<String> publicAddress) throws Exception{
		Map<String,Set<String>> publicPortIPMap = new HashMap<>();
		if(nsgList==null || nsgList.size()==0) {
			Set<String> publicIPs= new HashSet<>();
			publicIPs.add(PacmanRuleConstants.ALL);
			publicPortIPMap.put(PacmanRuleConstants.ALL, publicIPs);
			return publicPortIPMap;
			
		} else {
			JsonObject subnetNsg = null;
			JsonObject nicNsg = null;
			for (JsonElement vmNSGJsonElement : nsgList) {
				JsonObject eachNSG = vmNSGJsonElement.getAsJsonObject();
				String attachedToType = eachNSG.has(PacmanRuleConstants.ATTACHED_TO_TYPE)
						? eachNSG.get(PacmanRuleConstants.ATTACHED_TO_TYPE).getAsString()
						: null;
				if (!StringUtils.isEmpty(attachedToType)) {
					if (attachedToType.equals(PacmanRuleConstants.SUBNET)) {
						subnetNsg=vmNSGJsonElement.getAsJsonObject();
					} else {
						nicNsg=vmNSGJsonElement.getAsJsonObject();
					}
				}
			}
			publicPortIPMap= getPublicPorts(subnetNsg, nicNsg, esNsgUrl, region, subscription, publicAddress);
		}
		return publicPortIPMap;
	}

	/**
	 * @param subnetNsg
	 * @param nicNsg
	 * @param esNsgUrl
	 * @param region
	 * @param subscription
	 * @param publicAddress
	 * @return
	 * @throws Exception
	 */
	@SuppressWarnings("unchecked")
	private static Map<String,Set<String>> getPublicPorts(JsonObject subnetNsg, JsonObject nicNsg, String esNsgUrl, String region, String subscription,
			List<String> publicAddress)
			throws Exception {
		Map<String, Set<String>> publicPortIPMap = null;
		if(nicNsg!=null) {
			String nsgResourceId = nicNsg.get(PacmanRuleConstants.NSG).getAsString();
			Map<String, Object> nicPublicData  = isPublicallyAccessible(esNsgUrl, nsgResourceId,region,subscription,publicAddress);
			boolean isNICPublic = (boolean) nicPublicData.get(PacmanRuleConstants.IS_PUBLIC);
			boolean isSubnetPublic = false;
			Map<String, Set<String>> subnetRules = null;
			Map<String, Set<String>> nicRules = (Map<String, Set<String>>) nicPublicData.get(PacmanRuleConstants.PUBLIC_IPPORT_MAP);
										
			Map<String, Object> subnetPublicData = new HashMap<>();
			if (subnetNsg !=null) {
				nsgResourceId = subnetNsg.get(PacmanRuleConstants.NSG).getAsString();
				subnetPublicData = isPublicallyAccessible(esNsgUrl, nsgResourceId,region,subscription,publicAddress); 
				isSubnetPublic = (boolean) subnetPublicData.get(PacmanRuleConstants.IS_PUBLIC);
				subnetRules = (Map<String, Set<String>>) subnetPublicData.get(PacmanRuleConstants.PUBLIC_IPPORT_MAP);
			}
			
			if (isNICPublic) {
				List<String> nicDestinationPort = (List<String>) nicPublicData
						.get(PacmanRuleConstants.PUBLIC_PORT);
				if (isSubnetPublic) {
					List<String> subnetDestinationPort = (List<String>) subnetPublicData.get(PacmanRuleConstants.PUBLIC_PORT);
					List<String> commonPorts = PortUtils.getCommonPorts(nicDestinationPort,subnetDestinationPort);
					if(!commonPorts.isEmpty()) {
						publicPortIPMap = getPublicPortIPMap(nicRules, subnetRules, commonPorts);
					}
					
				} else if (subnetNsg==null) {
					publicPortIPMap = nicRules;
				}
			}
		} else if(subnetNsg!=null) {
			String nsgResourceId = subnetNsg.get(PacmanRuleConstants.NSG).getAsString();
			Map<String, Object> subnetPublicData = isPublicallyAccessible(esNsgUrl, nsgResourceId,region,subscription,publicAddress);
			boolean isSubnetPublic = (boolean) subnetPublicData.get(PacmanRuleConstants.IS_PUBLIC);
			Map<String, Set<String>> subnetRules = (Map<String, Set<String>>) subnetPublicData.get(PacmanRuleConstants.PUBLIC_IPPORT_MAP);
			
			if (isSubnetPublic) {
				publicPortIPMap = subnetRules;
			}
		}
		return publicPortIPMap;
	}
	
	/**
	 * Gets the public port IP map.
	 *
	 * @param nicRules the nic rules
	 * @param subnetRules the subnet rules
	 * @param commonPorts the common ports
	 * @return the public port IP map
	 */
	private static Map<String, Set<String>> getPublicPortIPMap(Map<String, Set<String>> nicRules, Map<String, Set<String>> subnetRules,
			List<String> commonPorts) {
    	Map<String, Set<String>> publicPortIPMap = new HashMap<>();
    	if(null!= nicRules && null!= subnetRules) {
			for(String port: commonPorts) {
				Set<String> nicIPs = getNonPermittedAddressesForPort(port, nicRules);
				Set<String> subnetIPs = getNonPermittedAddressesForPort(port, subnetRules);
				Set<String> publicIPs = getNicIPRangesCommonWithSubnet(nicIPs, subnetIPs);
				if(!publicIPs.isEmpty()) {
					publicPortIPMap.put(port, publicIPs);	
				}
			}
    	}
		return publicPortIPMap;
	}
	
	/**
	 * Get NIC IP ranges that has common range with subnet IP ranges
	 * @param nicIPs
	 * @param subnetIPs
	 * @return
	 */
	public static Set<String> getNicIPRangesCommonWithSubnet(Set<String> nicIPs,
			Set<String> subnetIPs) {
		Set<String> commonRanges = new HashSet<>();
		
		for(String nicIP : nicIPs) {
			List<String> publicIps = new ArrayList<>(Arrays.asList(IP_ALL.split(PacmanSdkConstants.COMMA)));
			if(publicIps.contains(nicIP)) {
				commonRanges.addAll(subnetIPs);
			} else {
				String commonRange = IPUtils.getCommonRange(nicIP, subnetIPs);
				if(null!= commonRange) {
					commonRanges.add(nicIP);
				}
			}
		}
		return commonRanges;
	}
    

    /**
     * Function for getting VM Load balancer detail
     * @param resourceId
     * @param resourceGroupName
     * @param region
     * @param subscription
     * @param ruleParam
     * @param nicIds 
     * @return
     * @throws Exception
     */
    public static JsonArray getLoadbalancer (String resourceId, String resourceGroupName, String region, String subscription, Map<String, String> ruleParam, Set<String> nicIds) throws Exception {
		Map<String, Object> mustFilterMap = new HashMap<>();
		mustFilterMap.put(PacmanRuleConstants.LATEST, true);
		mustFilterMap.put(PacmanRuleConstants.AZURE_SUBSCRIPTION, subscription);
		mustFilterMap.put(PacmanRuleConstants.REGION, region);
		
		HashMultimap<String, Object> shouldFilterMap =  HashMultimap.create();
		String rId = resourceId.replaceAll(resourceGroupName, PacmanUtils.getCaseInsensitiveRegex(resourceGroupName));
		
		JsonObject virtualMachine = new JsonObject();
		virtualMachine.addProperty("backend.virtualMachineIds.keyword", rId);
		shouldFilterMap.put("regexp",virtualMachine);
		
		Map<String, Object> termsMap = new HashMap<>();
		termsMap.put("inboundNATRules.backendNetworkInterfaceId.keyword", nicIds);
		
		shouldFilterMap.put("terms",termsMap);
		
		String loadbalncerUrl = PacmanUtils.formatUrl(ruleParam,PacmanRuleConstants.LOADBALANCER_ES_URL,PacmanRuleConstants.ES_URI);
		if (!PacmanUtils.doesAllHaveValue(loadbalncerUrl)) {
			logger.info(PacmanRuleConstants.MISSING_PARAMS);
			throw new InvalidInputException(PacmanRuleConstants.MISSING_PARAMS);
		}
		return PacmanUtils.getValueFromElasticSearchAsJsonArray(loadbalncerUrl, mustFilterMap, shouldFilterMap, null,null);
    }
    
    /**
	 * Function for checking if a NSG is publicly accessible
	 * 
	 * @param nsgRuleUrl
	 * @param resourceId
	 * @return
	 * @throws Exception
	 */
	@SuppressWarnings("unchecked")
	public static Map<String, Object> isPublicallyAccessible(String nsgRuleUrl, String resourceId, String region,
			String subscription, List<String> allowedPublicAddresses) throws Exception {
		Map<String, Object> returnData = new HashMap<>();
		returnData.put(PacmanRuleConstants.IS_PUBLIC, false);
		returnData.put(PacmanRuleConstants.PUBLIC_PORT, new ArrayList<String>());
		returnData.put(PacmanRuleConstants.PUBLIC_IPS, new ArrayList<String>());
		returnData.put(PacmanRuleConstants.PUBLIC_IPPORT_MAP, new HashMap<String, Set<String>>());

		JsonArray ruleList = getNSGRuleList(nsgRuleUrl, resourceId,region,subscription);
		logger.debug("nsg -> {}", resourceId);
		List<NSGRuleDTO> nsgRules = getNSGRuleDTOs(ruleList);
		
		//sort by priority
		nsgRules.sort(Comparator.comparingInt(NSGRuleDTO::getPriority));
		Set<String> ports = new HashSet<>();
		nsgRules.stream().forEach(nsgRule -> {
			ports.addAll(nsgRule.getDestinationPortRanges());
		});
		
		ports.stream().forEach(port->{
			List<String> sourceAddresses = getAllowedSourceAddressesForPort(port, nsgRules);
			// if the least priority rule has action allow, then add to the public rules 
			if(null!= sourceAddresses && !sourceAddresses.isEmpty()) {
				Set<String> publicAddresses = IPUtils.filterPublicAddressOutsidePermittedRange(sourceAddresses, allowedPublicAddresses);
				if(null!=publicAddresses && !publicAddresses.isEmpty()) {
					returnData.put(PacmanRuleConstants.IS_PUBLIC, true);
					((List<String>)returnData.get(PacmanRuleConstants.PUBLIC_PORT)).add(port);
					((Map<String, Set<String>>)returnData.get(PacmanRuleConstants.PUBLIC_IPPORT_MAP)).put(port, publicAddresses);
					((List<String>)returnData.get(PacmanRuleConstants.PUBLIC_IPS)).addAll(publicAddresses);
				}
			}
		});
		logger.debug("port IP map -> {}",returnData.get(PacmanRuleConstants.PUBLIC_IPPORT_MAP));
		return returnData;
	}
	
	/**
	 * This method gets all the allowed rules for a port from a set of rules sorted by priority
	 * @param port
	 * @param rules
	 * @return 
	 */
	public static List<String> getAllowedSourceAddressesForPort(String port, List<NSGRuleDTO> sortedNsgRules) {
		List<String> sourceAddresses = new ArrayList<>();
		List<String> deniedAddresses = new ArrayList<>();
		for(NSGRuleDTO rule : sortedNsgRules){
			if(ruleContainsDestinationPort(port, rule)) {
				if(PacmanRuleConstants.ALLOW.equals(rule.getAccess())) {
					List<String> sourceAddressPrefixes = rule.getSourceAddressPrefixes();
					Set<String> allowedRanges =IPUtils.filterAddressOutsideGivenRanges(sourceAddressPrefixes, deniedAddresses);
					if(null != allowedRanges && !allowedRanges.isEmpty()) {
						sourceAddresses.addAll(allowedRanges);
					}
				} else {
					deniedAddresses.addAll(validateAndGetDeniedAddresses(rule));
				}
			}
		}
		logger.debug("{}: sourceAddresses -> {}", port, sourceAddresses);
		logger.debug("{}: denied Addresses -> {}", port, deniedAddresses);
		return sourceAddresses;
	}

	/**
	 * Validate and get denied addresses.
	 *
	 * @param rule the rule
	 * @return the list
	 */
	private static List<String> validateAndGetDeniedAddresses(NSGRuleDTO rule) {
		List<String> deniedAddresses = new ArrayList<>();
		List<String> publicIps = new ArrayList<>(Arrays.asList(IP_ALL.split(PacmanSdkConstants.COMMA)));
		
		List<String> sourceAddressPrefixes = rule.getSourceAddressPrefixes();
		sourceAddressPrefixes.stream().forEach(address -> {
			if(publicIps.contains(address)) {
				deniedAddresses.add(PacmanSdkConstants.ASTERISK);
			} else if (IPUtils.validIPv4(address)) {
				deniedAddresses.add(address);
			}
		});
		return deniedAddresses;
	}

	/**
	 * Rule contains destination port.
	 *
	 * @param port the port
	 * @param rule the rule
	 * @return true, if successful
	 */
	private static boolean ruleContainsDestinationPort(String port, NSGRuleDTO rule) {
		boolean contains = false;
		Set<String> destinationPortRanges = new HashSet<>(rule.getDestinationPortRanges());
		if(destinationPortRanges.contains(PacmanSdkConstants.ASTERISK)) {
			contains=true;
		} else if(PacmanSdkConstants.ASTERISK.equals(port)) {
			contains= destinationPortRanges.contains(PacmanSdkConstants.ASTERISK);
		} else if(port.contains(PacmanSdkConstants.HYPHEN)) {
			List<String> commonPorts =PortUtils.getCommonPortRange(rule.getDestinationPortRanges(), port);
			if(null!=commonPorts && !commonPorts.isEmpty()) {
				contains=true;
			}
		}else {
			contains= PortUtils.containsPort(Integer.parseInt(port), destinationPortRanges);
		}
		return contains;
	}
		
	/**
	 * Build DTOs from NSG rules Json
	 * @param nsgRulesJson
	 * @return NSGRuleDTOs
	 */
	private static List<NSGRuleDTO> getNSGRuleDTOs(JsonArray nsgRulesJson) {
		List<NSGRuleDTO> nsgRuleDTOs = new ArrayList<>();
		if(null!= nsgRulesJson && nsgRulesJson.isJsonArray() && nsgRulesJson.size()>0) {
			for (JsonElement rule : nsgRulesJson) {
				JsonObject firewallRule = rule.getAsJsonObject();
				Gson gson = new Gson();
				NSGRuleDTO ipRule= gson.fromJson(firewallRule, NSGRuleDTO.class);
				nsgRuleDTOs.add(ipRule);
			}
		}else {
			throw new RuleExecutionFailedExeption("nsg rules are null or empty");
		}
		return nsgRuleDTOs;
	}
	
	/**
	 * Function for creating the rule list of a particular NSG with resource id
	 * 
	 * @param esUrl
	 * @param resourceId
	 * @return
	 * @throws Exception
	 */
	public static JsonArray getNSGRuleList(String esUrl, String resourceId,String region,String subscription) throws Exception {

		String rId = resourceId.charAt(0) == '/' ? resourceId.substring(1) : resourceId;
		JsonArray nsgRuleList = new JsonArray();
		Map<String, Object> mustFilter = new HashMap<>();
		
		String nsgIdRegex = PacmanUtils.getCaseInsensitiveRegex(rId);
		JsonObject nsgId = new JsonObject();
		nsgId.addProperty(PacmanUtils.convertAttributetoKeyword(PacmanRuleConstants.RESOURCE_ID), nsgIdRegex);
		mustFilter.put("regexp",nsgId);
		
		//mustFilter.put(PacmanUtils.convertAttributetoKeyword(PacmanRuleConstants.RESOURCE_ID), rId);
		mustFilter.put(PacmanRuleConstants.LATEST, true);
		mustFilter.put(PacmanUtils.convertAttributetoKeyword(PacmanRuleConstants.REGION), region);
		mustFilter.put(PacmanUtils.convertAttributetoKeyword(PacmanRuleConstants.AZURE_SUBSCRIPTION), subscription);
		JsonObject resultJson = RulesElasticSearchRepositoryUtil.getQueryDetailsFromES(esUrl, mustFilter, null, null,null, 0, null, null, null);
		JsonArray hits = PacmanUtils.getHitsFromESResponse(resultJson);
		if (hits!=null && hits.size() > 0) {
			JsonObject firstObject = hits.get(0).getAsJsonObject();
			JsonObject sourceJson = firstObject.get(PacmanRuleConstants.SOURCE).getAsJsonObject();
			if (null != sourceJson && sourceJson.has(PacmanRuleConstants.INBOUND_SECURITY_RULES)) {
				nsgRuleList = sourceJson.get(PacmanRuleConstants.INBOUND_SECURITY_RULES).getAsJsonArray();
			}
		}
		return nsgRuleList;
	}
	
	/**
	 * Function for getting the NSG for a particular virtual machine with the
	 * resource id
	 * 
	 * @param esUrl
	 * @param resourceId
	 * @return
	 * @throws Exception
	 */
	public static Map<String, Object> getVMResourceNSGList(String esUrl, String resourceId,String region,String subscription) throws Exception {

		Map<String, Object> retData = new HashMap<>();
		JsonArray nsgList = new JsonArray();
		Map<String, Object> mustFilter = new HashMap<>();

		JsonObject virtualMachine = new JsonObject();
		virtualMachine.addProperty(PacmanUtils.convertAttributetoKeyword(PacmanRuleConstants.RESOURCE_ID), resourceId);
		mustFilter.put("regexp",virtualMachine);
		mustFilter.put(PacmanRuleConstants.LATEST, true);
		mustFilter.put(PacmanUtils.convertAttributetoKeyword(PacmanRuleConstants.REGION), region);
		mustFilter.put(PacmanUtils.convertAttributetoKeyword(PacmanRuleConstants.AZURE_SUBSCRIPTION), subscription);
		JsonObject resultJson = RulesElasticSearchRepositoryUtil.getQueryDetailsFromES(esUrl, mustFilter, null, null,null, 0, null, null, null);
		JsonArray hits = PacmanUtils.getHitsFromESResponse(resultJson);
		if (hits!=null && hits.size() > 0) {
			JsonObject firstObject = hits.get(0).getAsJsonObject();
			JsonObject sourceJson = firstObject.get(PacmanRuleConstants.SOURCE).getAsJsonObject();
			if (null != sourceJson && sourceJson.has(PacmanRuleConstants.NETWORK_SECURITY_GROUP)) {
				nsgList = sourceJson.get(PacmanRuleConstants.NETWORK_SECURITY_GROUP).getAsJsonArray();
				retData.put(PacmanRuleConstants.VM_NSG_LIST, nsgList);
				retData.put(PacmanRuleConstants.VM_NAME, sourceJson.get(PacmanRuleConstants.VM_NAME).getAsString());
				retData.put(PacmanRuleConstants.VM_NIC_LIST, sourceJson.get(PacmanRuleConstants.VM_NIC_LIST).getAsJsonArray());
			}
		}

		return retData;
	}

	/**
	 * Function for getting the detail of a virtual machine with the
	 * resource id
	 * 
	 * @param esUrl
	 * @param resourceId
	 * @return
	 * @throws Exception
	 */
	public static JsonObject getVMResourceDetail(String esUrl, String vmId, String nicId, String region,String subscription) throws Exception {
		JsonObject retData = new JsonObject();
		Map<String, Object> mustFilter = new HashMap<>();
		
		if(null!=vmId) {
			String resourceId = PacmanUtils.getCaseInsensitiveRegex(vmId);
			JsonObject virtualMachine = new JsonObject();
			virtualMachine.addProperty(PacmanUtils.convertAttributetoKeyword(PacmanRuleConstants.RESOURCE_ID), resourceId);
			mustFilter.put("regexp",virtualMachine);
		} else {
			String nicIdRegex = PacmanUtils.getCaseInsensitiveRegex(getValidAzureResourceId(nicId));
			JsonObject networkInterfaceIds = new JsonObject();
			networkInterfaceIds.addProperty(PacmanUtils.convertAttributetoKeyword("networkInterfaceIds"), nicIdRegex);
			mustFilter.put("regexp",networkInterfaceIds);
			
		}
		mustFilter.put(PacmanRuleConstants.LATEST, true);
		mustFilter.put(PacmanUtils.convertAttributetoKeyword(PacmanRuleConstants.REGION), region);
		mustFilter.put(PacmanUtils.convertAttributetoKeyword(PacmanRuleConstants.AZURE_SUBSCRIPTION), subscription);
		JsonObject resultJson = RulesElasticSearchRepositoryUtil.getQueryDetailsFromES(esUrl, mustFilter, null, null,null, 0, null, null, null);
		JsonArray hits = PacmanUtils.getHitsFromESResponse(resultJson);
		if (hits!=null && hits.size() > 0) {
			JsonObject firstObject = hits.get(0).getAsJsonObject();
			retData = firstObject.get(PacmanRuleConstants.SOURCE).getAsJsonObject();
		}

		return retData;
	}

	/**
	 * Gets the valid azure resource id.
	 *
	 * @param resourceId the resource id
	 * @return the valid azure resource id
	 */
	private static String getValidAzureResourceId(String resourceId) {
		return (!resourceId.isEmpty() && resourceId.charAt(0) == '/') ? resourceId:"/".concat(resourceId);
	}
	
	

	/**
	 * Function for checking if a NIC is attached to any subnet from the list
	 * 
	 * @param resourceId
	 * @param subnetList
	 * @return
	 */
	public static int getIndexSubnetResourceIdFromJsonArray(String resourceId, JsonArray subnetList) {
		for (int subnetIndex = 0; subnetIndex < subnetList.size(); subnetIndex++) {
			JsonObject subnetObject = subnetList.get(subnetIndex).getAsJsonObject();
			if (subnetObject.has(PacmanRuleConstants.ATTACHED_TO)) {
				String nsgResourceId = subnetObject.get(PacmanRuleConstants.ATTACHED_TO).getAsString();
				if (resourceId.equals(nsgResourceId)) {
					return subnetIndex;
				}
			}
		}
		return PacmanRuleConstants.SUBNET_NOT_FOUND;
	}

	/**
	 * Function for getting the public inBoundNATports of a load balancer
	 * @param inboundNATRules
	 * @param vmNICs
	 * @param nicPublicPort
	 * @param subnetPublicPort
	 * @return
	 */
	public static Set<Map<String, String>> getPublicInBoundNATPorts (JsonArray inboundNATRules, Map<String, Set<String>> publicPortMap) {
		Set<Map<String, String>> matchingInboundNATPorts = new HashSet<>();
		
		for (JsonElement inboundNATRuleElmt : inboundNATRules) {
			if(inboundNATRuleElmt.isJsonObject()){
				JsonObject inboundNATRule = inboundNATRuleElmt.getAsJsonObject();
				if(inboundNATRule.has(BACKEND_NETWORK_INTERFACE_ID) && !inboundNATRule.get(BACKEND_NETWORK_INTERFACE_ID).isJsonNull()) {
					String backendNetworkInterfaceId = inboundNATRule.get(BACKEND_NETWORK_INTERFACE_ID).getAsString();
					String backendPort = inboundNATRule.get(PacmanRuleConstants.BACK_END_PORTS).getAsString();
					String frontendPort = inboundNATRule.get(PacmanRuleConstants.FRONT_END_PORTS).getAsString();
					if (publicPortMap.containsKey(backendNetworkInterfaceId)
							&& PortUtils.containsPort(Integer.valueOf(backendPort), publicPortMap.get(backendNetworkInterfaceId))) {
						Map<String, String> publicPorts = new HashMap<>();
						publicPorts.put(PacmanRuleConstants.LM_FRONTENDPORTS, frontendPort);
						publicPorts.put(PacmanRuleConstants.LM_BACKENDPORTS, backendPort);
						matchingInboundNATPorts.add(publicPorts);
					}
				}
			}
		}
		return matchingInboundNATPorts;
	}
	

	/**
	 * Function for getting the public loadBalnacing ports of a load balancer
	 * @param loadBalancingRules
	 * @param nicId 
	 * @param poolNicMap 
	 * @param nicPublicPort
	 * @param subnetPublicPort
	 * @return
	 */
	public static Set<Map<String, String>> getPublicLoadBalancingPorts (JsonArray loadBalancingRules, Map<String, List<String>> poolNicMap, Map<String, Set<String>> publicPortsMap) {
		Set<Map<String, String>> matchingLoadBalancingPorts = new HashSet<>();
		for (JsonElement loadBalancingRulesElmt : loadBalancingRules) {
			if(loadBalancingRulesElmt.isJsonObject()){
				JsonObject loadBalancingRule = loadBalancingRulesElmt.getAsJsonObject();
				String poolName = loadBalancingRule.get("backendPoolName").getAsString();
				String frontendPort = loadBalancingRule.get(PacmanRuleConstants.FRONT_END_PORTS).getAsString();
				String backendPort = loadBalancingRule.get(PacmanRuleConstants.BACK_END_PORTS).getAsString();
				if(poolNicMap.get(poolName)!=null && !poolNicMap.get(poolName).isEmpty()) {
					List<String> nicList = poolNicMap.get(poolName);
					for(Entry<String, Set<String>> nicPublicPortsEntry : publicPortsMap.entrySet()) {
						String nicId = nicPublicPortsEntry.getKey();
						Set<String> nicPublicPorts = nicPublicPortsEntry.getValue();
						if(nicList.contains(nicId) && PortUtils.containsPort(Integer.valueOf(backendPort), nicPublicPorts)) {
							Map<String, String> publicPorts = new HashMap<>();
							publicPorts.put(PacmanRuleConstants.LM_FRONTENDPORTS, frontendPort);
							publicPorts.put(PacmanRuleConstants.LM_BACKENDPORTS, backendPort);
							matchingLoadBalancingPorts.add(publicPorts);
						}
					}
				}
			}
		}
		return matchingLoadBalancingPorts;
	}
	
	/**
	 * Function for getting the front end ports configured for all load balancer rules
	 * @param loadBalancerRules
	 * @return
	 */
	public static Set<Map<String, String>> getLBFrontEndPorts(JsonArray loadBalancerRules) {
		Set<Map<String, String>> lBFrontendPorts = new HashSet<>();
		for (JsonElement loadBalancerRuleElmt : loadBalancerRules) {
			JsonObject loadBalancerRule = loadBalancerRuleElmt.getAsJsonObject();
			String frontendPort = loadBalancerRule.get(PacmanRuleConstants.FRONT_END_PORTS).getAsString();
			String backendPort = loadBalancerRule.get(PacmanRuleConstants.BACK_END_PORTS).getAsString();
			Map<String, String> publicPorts = new HashMap<>();
			publicPorts.put(PacmanRuleConstants.LM_FRONTENDPORTS, frontendPort);
			publicPorts.put(PacmanRuleConstants.LM_BACKENDPORTS, backendPort);
			lBFrontendPorts.add(publicPorts);
		}
		return lBFrontendPorts;
	}
	
	/**
	 * Gets the string set from map set.
	 *
	 * @param mapSet the map set
	 * @param mapKey the map key
	 * @return the string set from map set
	 */
	public static Set<String> getStringSetFromMapSet(Set<Map<String, String>> mapSet, String mapKey) {
		return mapSet.stream().map(map -> map.getOrDefault(mapKey, "")).collect(Collectors.toSet());
	}
	
	/**
	 * Gets the filter map from map set.
	 *
	 * @param mapSet the map set
	 * @param mapKey the map key
	 * @param filterValue the filter value
	 * @return the filter map from map set
	 */
	public static Map<String, String> getFilterMapFromMapSet(Set<Map<String, String>> mapSet, String mapKey, String filterValue) {
		return mapSet.stream().filter(map -> map.getOrDefault(mapKey, "").equals(filterValue)).findAny().orElse(Maps.newHashMap());
	}

	/**
	 * Gets the classic VM instance details.
	 *
	 * @param urlPath the url path
	 * @param resourceId the resource id
	 * @param region the region
	 * @param subscription the subscription
	 * @return the classic VM instance details
	 * @throws Exception the exception
	 */
	public static JsonObject getClassicVMInstanceDetails(String urlPath, String resourceId,
			String region, String subscription) throws Exception {
		JsonObject instanceDetails = null;
		
		String pacmanHost = PacmanUtils.getPacmanHost(PacmanRuleConstants.ES_URI);
		String esUrl = pacmanHost+urlPath;
		
		Map<String, Object> mustFilter = new HashMap<>();
		mustFilter.put(PacmanRuleConstants.LATEST, true);
		mustFilter.put(PacmanUtils.convertAttributetoKeyword(PacmanRuleConstants.RESOURCE_ID), resourceId);
		mustFilter.put(PacmanUtils.convertAttributetoKeyword(PacmanRuleConstants.REGION), region);
		mustFilter.put(PacmanUtils.convertAttributetoKeyword(PacmanRuleConstants.AZURE_SUBSCRIPTION), subscription);
		
		JsonObject resultJson = RulesElasticSearchRepositoryUtil.getQueryDetailsFromES(esUrl, mustFilter, null, null,null, 0, null, null, null);
		
		JsonArray hits = PacmanUtils.getHitsFromESResponse(resultJson);
		if (hits!=null && hits.size() > 0) {
			JsonObject source = hits.get(0).getAsJsonObject().get(PacmanRuleConstants.SOURCE).getAsJsonObject();
			JsonElement instanceDetailsJson =source.get(PacmanRuleConstants.INSTANCE_VIEW);
			if(instanceDetailsJson!=null) {
				instanceDetails =instanceDetailsJson.getAsJsonObject();
			}
		}

		return instanceDetails;
	}
	
	/**
	 * Function for getting the subnet for an nic
	 * 
	 * @param esUrl
	 * @param nicId
	 * @return
	 * @throws Exception
	 */
	public static Map<String, Object> getNicDetails(String esUrl, String nicId) throws Exception {

		String rId = nicId.charAt(0) == '/' ? nicId.substring(1) : nicId;
		Map<String, Object> nicDetails = new HashMap<>();
		String subnet=null;
		String publicIP =null;
		boolean hasPublicIP = false;
		Map<String, Object> mustFilter = new HashMap<>();
		
		String nicIdRegex = PacmanUtils.getCaseInsensitiveRegex(rId);
		JsonObject resourceId = new JsonObject();
		resourceId.addProperty(PacmanUtils.convertAttributetoKeyword(PacmanRuleConstants.RESOURCE_ID), nicIdRegex);
		mustFilter.put("regexp",resourceId);
		
		//mustFilter.put(PacmanUtils.convertAttributetoKeyword(PacmanRuleConstants.RESOURCE_ID), rId);
		mustFilter.put(PacmanRuleConstants.LATEST, true);
		JsonObject resultJson = RulesElasticSearchRepositoryUtil.getQueryDetailsFromES(esUrl, mustFilter, null, null,null, 0, null, null, null);
		JsonArray hits = PacmanUtils.getHitsFromESResponse(resultJson);
		if (hits!=null && hits.size() > 0) {
			JsonObject firstObject = hits.get(0).getAsJsonObject();
			JsonObject sourceJson = firstObject.get(PacmanRuleConstants.SOURCE).getAsJsonObject();
			if (null != sourceJson && sourceJson.has(PacmanRuleConstants.NIC_IP_CONFIG)) {
				JsonArray ipConfigs = sourceJson.get(PacmanRuleConstants.NIC_IP_CONFIG).getAsJsonArray();
				if(ipConfigs.size()>=1) {
					subnet = ipConfigs.get(0).getAsJsonObject().get("subnetName").getAsString();
					for(JsonElement ipConfigJson : ipConfigs) {
						JsonObject ipConfig = ipConfigJson.getAsJsonObject();
						if(ipConfig.has("primary") && ipConfig.get("primary").getAsBoolean()) {
							if (ipConfig.has(PacmanRuleConstants.PUBLIC_IP_ADDRESS)
									&& !ipConfig.get(PacmanRuleConstants.PUBLIC_IP_ADDRESS).isJsonNull()
									&& !ipConfig.get(PacmanRuleConstants.PUBLIC_IP_ADDRESS).getAsString().isEmpty()) {
								hasPublicIP = true;
								publicIP = ipConfig.get(PacmanRuleConstants.PUBLIC_IP_ADDRESS).getAsString();
							}
							break;
						}
					}
				}
			}
		}
		nicDetails.put("hasPublicIP", hasPublicIP);
		nicDetails.put("subnet", subnet);
		nicDetails.put("publicIP", publicIP);
		return nicDetails;
	}
		
	/**
	 * This method gets all the IPs for a port from port IP map
	 * @param port
	 * @param rules
	 * @return 
	 */
	public static Set<String> getNonPermittedAddressesForPort(String port, Map<String, Set<String>> portIPMap) {
		Set<String> ipList = new HashSet<>();
		for(Entry<String, Set<String>> portIP : portIPMap.entrySet()) {
			if(PortUtils.isPortInRange(port, portIP.getKey())) {
				ipList.addAll(portIP.getValue());
			}
		}
		return ipList;
	}

}
