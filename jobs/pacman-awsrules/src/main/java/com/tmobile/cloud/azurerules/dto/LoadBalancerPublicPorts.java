package com.tmobile.cloud.azurerules.dto;

import java.util.Set;

public class LoadBalancerPublicPorts {
	
	Set<String> natFrontEndPorts;
	Set<String> natBackEndPorts;
	Set<String> lbFrontEndPorts;
	Set<String> lbBackEndPorts;
	
	public Set<String> getNatFrontEndPorts() {
		return natFrontEndPorts;
	}
	public void setNatFrontEndPorts(Set<String> natFrontEndPorts) {
		this.natFrontEndPorts = natFrontEndPorts;
	}
	public Set<String> getNatBackEndPorts() {
		return natBackEndPorts;
	}
	public void setNatBackEndPorts(Set<String> natBackEndPorts) {
		this.natBackEndPorts = natBackEndPorts;
	}
	public Set<String> getLbFrontEndPorts() {
		return lbFrontEndPorts;
	}
	public void setLbFrontEndPorts(Set<String> lbFrontEndPorts) {
		this.lbFrontEndPorts = lbFrontEndPorts;
	}
	public Set<String> getLbBackEndPorts() {
		return lbBackEndPorts;
	}
	public void setLbBackEndPorts(Set<String> lbBackEndPorts) {
		this.lbBackEndPorts = lbBackEndPorts;
	}

}
