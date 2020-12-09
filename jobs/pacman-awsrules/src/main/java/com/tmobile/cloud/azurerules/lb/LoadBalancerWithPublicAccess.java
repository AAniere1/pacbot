package com.tmobile.cloud.azurerules.lb;

import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.tmobile.cloud.awsrules.utils.PacmanUtils;
import com.tmobile.cloud.azurerules.dto.LoadBalancerPublicPorts;
import com.tmobile.cloud.azurerules.dto.NicPublicData;
import com.tmobile.cloud.azurerules.utils.CommonUtils;
import com.tmobile.cloud.azurerules.utils.LoadBalancerUtil;
import com.tmobile.cloud.azurerules.utils.VirtualMachineUtil;
import com.tmobile.cloud.constants.PacmanRuleConstants;
import com.tmobile.pacman.commons.PacmanSdkConstants;
import com.tmobile.pacman.commons.exception.RuleExecutionFailedExeption;
import com.tmobile.pacman.commons.rule.Annotation;
import com.tmobile.pacman.commons.rule.BaseRule;
import com.tmobile.pacman.commons.rule.PacmanRule;
import com.tmobile.pacman.commons.rule.RuleResult;


/**
 * This is azure rule for checking if the load balancer is open to internet or not
 *
 */
@PacmanRule(key = "check-for-loadbalancer-public-access", desc = "This is azure rule for checking if the load balancer is open to internet or not", severity = PacmanSdkConstants.SEV_HIGH, category = PacmanSdkConstants.SECURITY)
public class LoadBalancerWithPublicAccess extends BaseRule{
		
	private static final String ES_KEY_LOAD_BALANCING_RULES = "loadBalancingRules";

	private static final String ES_KEY_INBOUND_NAT_RULES = "inboundNATRules";

	private static final Logger logger = LoggerFactory.getLogger(LoadBalancerWithPublicAccess.class);
	
	public static final String PUBLIC_PORT_IP = "VM-%s Port-%s: ";
	private static final String VIOLATION_REASON = "Load Balancer with public accessibility found!";
	
	private static final String DB_KEY_NAT_BACK_END_PORTS = "natBackEndPublicPorts";
	private static final String DB_KEY_LB_BACK_END_PORTS = "lbBackEndPublicPorts";
	private static final String DB_KEY_NAT_FRONT_END_PORTS = "natFrontEndPublicPorts";
	private static final String DB_KEY_LB_FRONT_END_PORTS = "lbFrontEndPublicPorts";

	private static final String ISSUE_DETAILS_KEY_LB_FRONT_END_PORTS = "LBFrontEndPublicPorts_%s";
	private static final String ISSUE_DETAILS_KEY_LB_BACK_END_PORTS = "LBBackEndPublicPorts_%s";
	private static final String ISSUE_DETAILS_KEY_NAT_FRONT_END_PORTS = "NatFrontEndPublicPorts_%s";
	private static final String ISSUE_DETAILS_KEY_NAT_BACK_END_PORTS = "NatBackEndPublicPorts_%s";
		
	@Override
	public RuleResult execute(Map<String, String> ruleParam, Map<String, String> resourceAttributes) {
		
        MDC.put("executionId", ruleParam.get("executionId")); 
        MDC.put("ruleId", ruleParam.get(PacmanSdkConstants.RULE_ID)); 

        String resourceId = resourceAttributes.get(PacmanRuleConstants.RESOURCE_ID);
    	String esLoadBalancerUrl = ruleParam.get(PacmanRuleConstants.ES_LOADBALANCER_URL);
		
    	String pacmanHost = PacmanUtils.getPacmanHost(PacmanRuleConstants.ES_URI);
    	
		logger.debug("========LbPublicAccessRule started=========");
		
		try {
			JsonObject loadBalancerDetail = LoadBalancerUtil.getLoadBalancerDetailFromES(pacmanHost+esLoadBalancerUrl, resourceId);
			List<String> publicIpAddress = PacmanUtils.getStringListFromJsonArray(loadBalancerDetail.getAsJsonArray(PacmanRuleConstants.PUBLIC_IP_ADDRESS_IDS));
			
			if (!publicIpAddress.isEmpty()) {
				LinkedHashMap<String, Object> issue = new LinkedHashMap<>();
				Map<String, Object> violationReasonMap = new HashMap<>();
				
				Map<String, List<String>> poolNicMap = LoadBalancerUtil.getLoadBalancerPoolNicMap(loadBalancerDetail.getAsJsonArray("backend"));
				List<String> natNics = LoadBalancerUtil.getLoadBalancerNatNics(loadBalancerDetail.getAsJsonArray(ES_KEY_INBOUND_NAT_RULES));
				
				Set<String> attachedNics = new HashSet<>();
				attachedNics.addAll(natNics);
				for(List<String> nics : poolNicMap.values()) {
					attachedNics.addAll(nics);
				}
			
				violationReasonMap.putAll(getViolationMap());
				
				for (String nicId : attachedNics) {
					if(null!= nicId && !nicId.isEmpty()) {
						issue.putAll(getNICPublicPorts(ruleParam, resourceAttributes, loadBalancerDetail, poolNicMap, nicId, violationReasonMap));
					}
				}
				
				if (!issue.isEmpty()) {
					logger.trace("========LBPublicAccess ended with an annotation=========");
					
					String description = violationReasonMap.getOrDefault(PacmanRuleConstants.VIOLATION_REASON, VIOLATION_REASON).toString();
					issue.put(PacmanRuleConstants.VIOLATION_REASON, description);
					
			        Annotation annotation = createAnnotation(ruleParam, resourceAttributes, String.join(",", publicIpAddress), issue);
			        return new RuleResult(PacmanSdkConstants.STATUS_FAILURE, PacmanRuleConstants.FAILURE_MESSAGE, annotation);
				}
			}
		} catch (Exception exception) {
            throw new RuleExecutionFailedExeption(exception.getMessage());
		}

		logger.debug("========LbPublicAccessRule ended=========");
		return new RuleResult(PacmanSdkConstants.STATUS_SUCCESS,PacmanRuleConstants.SUCCESS_MESSAGE);
	}

	private Map<String,Object> getViolationMap()
    {
    	String violationReason="{\"violationReason\":\"Load Balancer with public accessibility found!!\",\"lbFrontEndPublicPorts\":\"LBFrontEndPublicPorts_%s\", \"lbBackEndPublicPorts\":\"LBBackEndPublicPorts_%s\",\r\n"
    			+ "\"natFrontEndPublicPorts\":\"NatFrontEndPublicPorts_%s\", \"natBackEndPublicPorts\":\"NatBackEndPublicPorts_%s\", \"publicPortMap\":\"Non Permissible IP Ranges-%s\"}";
    	Gson gson = new Gson();
    	Map<String,Object> violationMap = gson.fromJson(violationReason, Map.class);
    	return violationMap;
    }

	@SuppressWarnings("unchecked")
	private LinkedHashMap<String, Object> getNICPublicPorts(Map<String, String> ruleParam, Map<String, String> resourceAttributes, JsonObject loadBalancerDetail,
			 Map<String, List<String>> poolNicMap, String nicId, Map<String, Object> violationReasonMap) throws Exception {
		
		LinkedHashMap<String, Object> publicPorts = new LinkedHashMap<>();
		Map<String, Set<String>> portIPMap = new HashMap<>();
		LoadBalancerPublicPorts lbPublicPorts = null;
		
		String pacmanHost = PacmanUtils.getPacmanHost(PacmanRuleConstants.ES_URI);
    	
		String esVirtualMachineRuleURl = ruleParam.get(PacmanRuleConstants.ES_VIRTUALMACHINE_URL);
		String region = resourceAttributes.get(PacmanRuleConstants.REGION);
		String subscription = resourceAttributes.get(PacmanRuleConstants.AZURE_SUBSCRIPTION);
		
		JsonArray inboundNATRules = loadBalancerDetail.get(ES_KEY_INBOUND_NAT_RULES).getAsJsonArray();
		JsonArray loadBalancingRules = loadBalancerDetail.get(ES_KEY_LOAD_BALANCING_RULES).getAsJsonArray();
		
		JsonObject vmDetail = VirtualMachineUtil.getVMResourceDetail(pacmanHost + esVirtualMachineRuleURl, null, nicId, region,subscription);
		String vmId= vmDetail.has(PacmanSdkConstants.RESOURCE_ID)?vmDetail.get(PacmanSdkConstants.RESOURCE_ID).getAsString():null;
		
		if (vmDetail.has(PacmanRuleConstants.STATUS) && vmDetail.get(PacmanRuleConstants.STATUS).getAsString().equals(PacmanRuleConstants.RUNNING_STATE)) {
			
			Map<String, Object> nsgData = VirtualMachineUtil.getVMResourceNSGList(pacmanHost + esVirtualMachineRuleURl, PacmanUtils.getCaseInsensitiveRegex(vmId), region,subscription);
			String vmName = (String) nsgData.getOrDefault(PacmanRuleConstants.VM_NAME, null);
			JsonArray vmNSGArray = (JsonArray) nsgData.getOrDefault(PacmanRuleConstants.VM_NSG_LIST, null);
			JsonArray vmNicArray = new JsonArray();
			vmNicArray.add(nicId);
									
			//Case: When No NSG For VM configured and NAT/LB Rule configured
			if (vmNSGArray == null || vmNSGArray.size() == 0) {
				Set<Map<String, String>> publicInBoundNATPorts = VirtualMachineUtil.getLBFrontEndPorts(inboundNATRules);
				Set<Map<String, String>> publicLoadBalancingPorts = VirtualMachineUtil.getLBFrontEndPorts(loadBalancingRules);
				lbPublicPorts =getLBPublicPorts(publicInBoundNATPorts, publicLoadBalancingPorts);
				
			} else {
				//Case: When NSG For VM configured and NAT/LB Rule configured
				
				Map<String, Object> nsgPublicDetail = VirtualMachineUtil.getVMPublicPorts(ruleParam,region, subscription, vmNSGArray, vmNicArray, true);
				List<NicPublicData> publicNic = (List<NicPublicData>) nsgPublicDetail.get(PacmanRuleConstants.PUBLIC_NIC);
				boolean isPublic = (boolean) nsgPublicDetail.get(PacmanRuleConstants.IS_PUBLIC);
				if (isPublic) {
					
					Map<String, Set<String>> publicPortsMap = new HashMap<>();
					
					for(NicPublicData nicData : publicNic) {
						publicPortsMap.put(nicData.getNicId(), nicData.getPublicPorts().keySet());
						portIPMap.putAll(nicData.getPublicPorts());
					}
					Set<Map<String, String>> publicInBoundNATPorts = VirtualMachineUtil.getPublicInBoundNATPorts(inboundNATRules, publicPortsMap);
					Set<Map<String, String>> publicLoadBalancingPorts = VirtualMachineUtil.getPublicLoadBalancingPorts(loadBalancingRules, poolNicMap, publicPortsMap);
					if(!publicInBoundNATPorts.isEmpty() || !publicLoadBalancingPorts.isEmpty()) {
						lbPublicPorts =getLBPublicPorts(publicInBoundNATPorts, publicLoadBalancingPorts);
					}
				}
			}
			if(null!= lbPublicPorts) {
				publicPorts =getPublicPortDetails(portIPMap, lbPublicPorts, vmName, violationReasonMap);
			}
		}
		return publicPorts;
	}
	
	@Override
	public String getHelpText() {
		return "This rule check for azure load balancer which is exposed to public";
	}
	
	private static Annotation createAnnotation(Map<String, String> ruleParam, Map<String, String> resourceAttributes, String publicipaddress,
			LinkedHashMap<String, Object> issue) {
		Map<String, String> additionalParams= new HashMap<>();
		additionalParams.put("LoadBalancerPublicIP", publicipaddress);
		
		logger.debug("========LbPublicAccessRule ended with an annotation =========");
		return CommonUtils.buildAnnotationForAzure(ruleParam, resourceAttributes, VIOLATION_REASON, issue, additionalParams);
	}
	
	private LoadBalancerPublicPorts getLBPublicPorts(Set<Map<String, String>> publicInBoundNATPorts,
			Set<Map<String, String>> publicLoadBalancingPorts) {
		LoadBalancerPublicPorts lbPublicPorts = new LoadBalancerPublicPorts();
		lbPublicPorts.setNatFrontEndPorts(VirtualMachineUtil.getStringSetFromMapSet(publicInBoundNATPorts, PacmanRuleConstants.LM_FRONTENDPORTS));
		lbPublicPorts.setNatBackEndPorts(VirtualMachineUtil.getStringSetFromMapSet(publicInBoundNATPorts, PacmanRuleConstants.LM_BACKENDPORTS));
		lbPublicPorts.setLbFrontEndPorts(VirtualMachineUtil.getStringSetFromMapSet(publicLoadBalancingPorts, PacmanRuleConstants.LM_FRONTENDPORTS));
		lbPublicPorts.setLbBackEndPorts(VirtualMachineUtil.getStringSetFromMapSet(publicLoadBalancingPorts, PacmanRuleConstants.LM_BACKENDPORTS));
		return lbPublicPorts;
	}
	
	private LinkedHashMap<String, Object> getPublicPortDetails(Map<String, Set<String>> portIPMap,
			LoadBalancerPublicPorts lbPublicPorts, String vmName, Map<String, Object> violationReasonMap) {
		LinkedHashMap<String, Object> publicPorts = new LinkedHashMap<>();
		Set<String> natFrontEndPorts = lbPublicPorts.getNatFrontEndPorts();
		Set<String> natBackEndPorts = lbPublicPorts.getNatBackEndPorts();
		Set<String> lbFrontEndPorts = lbPublicPorts.getLbFrontEndPorts();
		Set<String> lbBackEndPorts = lbPublicPorts.getLbBackEndPorts();
		
		if (null!=natFrontEndPorts && !natFrontEndPorts.isEmpty()) {
			String natFrontEndPortKey = String.format(violationReasonMap
					.getOrDefault(DB_KEY_NAT_FRONT_END_PORTS, ISSUE_DETAILS_KEY_NAT_FRONT_END_PORTS).toString(), vmName);
			publicPorts.put(natFrontEndPortKey, String.join(PacmanSdkConstants.DEFAULT_SEPARATOR,
					String.join(PacmanSdkConstants.COMMA, natFrontEndPorts)));

			String natBackEndPortKey = String.format(violationReasonMap
					.getOrDefault(DB_KEY_NAT_BACK_END_PORTS, ISSUE_DETAILS_KEY_NAT_BACK_END_PORTS).toString(), vmName);
			publicPorts.put(natBackEndPortKey, String.join(PacmanSdkConstants.DEFAULT_SEPARATOR,
					String.join(PacmanSdkConstants.COMMA, natBackEndPorts)));

			logger.trace("========LBPublicAccess found open ports through Virtual machine using inboundNAT Rules=========");
		}
		
		if (null!=lbFrontEndPorts && !lbFrontEndPorts.isEmpty()) {
			
			String lbFrontEndPortKey = String.format(violationReasonMap
					.getOrDefault(DB_KEY_LB_FRONT_END_PORTS, ISSUE_DETAILS_KEY_LB_FRONT_END_PORTS).toString(), vmName);
			publicPorts.put(lbFrontEndPortKey, String.join(PacmanSdkConstants.DEFAULT_SEPARATOR,
					String.join(PacmanSdkConstants.COMMA, lbFrontEndPorts)));

			String lbBackEndPortKey = String.format(violationReasonMap
					.getOrDefault(DB_KEY_LB_BACK_END_PORTS, ISSUE_DETAILS_KEY_LB_BACK_END_PORTS).toString(), vmName);
			publicPorts.put(lbBackEndPortKey, String.join(PacmanSdkConstants.DEFAULT_SEPARATOR,
					String.join(PacmanSdkConstants.COMMA, lbBackEndPorts)));

			logger.trace("========LBPublicAccess found open ports through Virtual machine using loadbalancing Rules=========");
		}
		if(!publicPorts.isEmpty()) {
			Set<String> publicBackEndPorts = new HashSet<>();
			publicBackEndPorts.addAll(lbBackEndPorts);
			publicBackEndPorts.addAll(natBackEndPorts);
			
			publicBackEndPorts.forEach(port->{
				
				Set<String> ipList = VirtualMachineUtil.getNonPermittedAddressesForPort(port, portIPMap);
				String nonPermittedIPs = ipList.parallelStream().map(publicIP -> publicIP.replace(PacmanSdkConstants.ASTERISK, PacmanRuleConstants.IP_ALL)).collect(Collectors.joining(PacmanSdkConstants.DEFAULT_SEPARATOR));
				String portKey = String.format(PUBLIC_PORT_IP, vmName, port);
				publicPorts.put(portKey, nonPermittedIPs);
			});
			
		}
		return publicPorts;
	}
  
}
