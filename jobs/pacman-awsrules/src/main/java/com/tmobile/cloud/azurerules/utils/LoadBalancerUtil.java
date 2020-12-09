package com.tmobile.cloud.azurerules.utils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.tmobile.cloud.awsrules.utils.PacmanUtils;
import com.tmobile.cloud.awsrules.utils.RulesElasticSearchRepositoryUtil;
import com.tmobile.cloud.constants.PacmanRuleConstants;

public class LoadBalancerUtil {
	private static final String BACKEND_NETWORK_INTERFACE_ID = "backendNetworkInterfaceId";
	/** The Constant logger. */
	private static final Logger logger = LoggerFactory.getLogger(LoadBalancerUtil.class);
	
	public static JsonObject getLoadBalancerDetailFromES(String esUrl, String resourceId) throws Exception {

		logger.info("<======esUrl for loadBalancerPublicIpAddress======>" + esUrl);
		JsonObject loadBalancerDetail = null;
		Map<String, Object> mustFilter = new HashMap<String, Object>();
		mustFilter.put(PacmanUtils.convertAttributetoKeyword(PacmanRuleConstants.RESOURCE_ID), resourceId);
		JsonObject resultJson = RulesElasticSearchRepositoryUtil.getQueryDetailsFromES(esUrl, mustFilter, null, null,
				null, 0, null, null, null);
		JsonArray hits = PacmanUtils.getHitsFromESResponse(resultJson);
		if (hits.size() > 0) {
			JsonObject firstObject = hits.get(0).getAsJsonObject();
			loadBalancerDetail = firstObject.get(PacmanRuleConstants.SOURCE).getAsJsonObject();
		}
		return loadBalancerDetail;
	}
	
	/**
	 * Function for getting all the VM attached to a load balancer
	 * @param lbbackends
	 * @return
	 */
	public static List<String> getLoadBalancerVMIds (JsonArray lbbackends) {
		List<String> lbVMIds = new ArrayList<>();
		if (!lbbackends.isJsonNull() && lbbackends.size() > 0) {
			for (JsonElement jsonElement : lbbackends) {
				JsonArray vmIdArray = jsonElement.getAsJsonObject().get("virtualMachineIds").getAsJsonArray();
				for(JsonElement vmIdEle : vmIdArray) {
					lbVMIds.add(vmIdEle.getAsString());
				}
			}
		}
		return lbVMIds;
	}
	
	public static List<String> getLoadBalancerNatNics(JsonArray inboundNATRules) {
		List<String> natNics = new ArrayList<>();
		if (!inboundNATRules.isJsonNull() && inboundNATRules.size() > 0) {
			for (JsonElement natRuleEle : inboundNATRules) {
				JsonObject natRule = natRuleEle.getAsJsonObject();
				if(natRule.has(BACKEND_NETWORK_INTERFACE_ID) && !natRule.get(BACKEND_NETWORK_INTERFACE_ID).isJsonNull()) {
					String nicId = natRule.get(BACKEND_NETWORK_INTERFACE_ID).getAsString();
					natNics.add(validateNicId(nicId) ? nicId.substring(1) : nicId);
				}
			}
		}
		return natNics;
	}

	private static boolean validateNicId(String nicId) {
		return !nicId.isEmpty() && nicId.charAt(0) == '/';
	}

	public static Map<String, List<String>> getLoadBalancerPoolNicMap(JsonArray lbbackends) {
		Map<String, List<String>> poolNicMap = new HashMap<>();
		if (!lbbackends.isJsonNull() && lbbackends.size() > 0) {
			for (JsonElement jsonElement : lbbackends) {
				List<String> nicList = new ArrayList<>();
				String poolName = jsonElement.getAsJsonObject().get("name").getAsString();
				JsonArray vmIdArray = jsonElement.getAsJsonObject().get("vmNicMap").getAsJsonArray();
				for(JsonElement vmNicMapEle : vmIdArray) {
					JsonObject vmNicMapObj = vmNicMapEle.getAsJsonObject();
					if(vmNicMapObj.has("nicId")) {
						String nicId = vmNicMapObj.get("nicId").getAsString();
						nicList.add(validateNicId(nicId) ? nicId.substring(1) : nicId);
					}
				}
				poolNicMap.put(poolName, nicList);
			}
		}
		return poolNicMap;
	}
}
