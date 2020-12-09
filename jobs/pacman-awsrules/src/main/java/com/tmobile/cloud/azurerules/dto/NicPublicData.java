package com.tmobile.cloud.azurerules.dto;

import java.util.Map;
import java.util.Set;

public class NicPublicData {
	
	private String nicId;
	private Map<String, Set<String>> publicPorts;
		
	public NicPublicData(String nic, Map<String, Set<String>> publicPorts) {
		this.nicId = nic;
		this.publicPorts = publicPorts;
	}
	
	public String getNicId() {
		return nicId;
	}
	public void setNicId(String nicId) {
		this.nicId = nicId;
	}
	public Map<String, Set<String>> getPublicPorts() {
		return publicPorts;
	}
	public void setPublicPorts(Map<String, Set<String>> publicPorts) {
		this.publicPorts = publicPorts;
	}
		
}
