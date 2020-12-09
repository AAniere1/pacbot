package com.tmobile.cloud.azurerules.dto;

import java.util.List;

public class NSGRuleDTO {
	private String name;
	private String description;
	private int priority;
	private String protocol;
	private String access;
    
	private List<String> sourceAddressPrefixes;
	private List<String> sourceApplicationSecurityGroupIds;
	private List<String> sourcePortRanges;
	private List<String> destinationPortRanges;
	private List<String> destinationApplicationSecurityGroupIds;
	private List<String> destinationAddressPrefixes;
	
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	public String getDescription() {
		return description;
	}
	public void setDescription(String description) {
		this.description = description;
	}
	public int getPriority() {
		return priority;
	}
	public void setPriority(int priority) {
		this.priority = priority;
	}
	public String getProtocol() {
		return protocol;
	}
	public void setProtocol(String protocol) {
		this.protocol = protocol;
	}
	public String getAccess() {
		return access;
	}
	public void setAccess(String access) {
		this.access = access;
	}
	public List<String> getSourceAddressPrefixes() {
		return sourceAddressPrefixes;
	}
	public void setSourceAddressPrefixes(List<String> sourceAddressPrefixes) {
		this.sourceAddressPrefixes = sourceAddressPrefixes;
	}
	public List<String> getSourceApplicationSecurityGroupIds() {
		return sourceApplicationSecurityGroupIds;
	}
	public void setSourceApplicationSecurityGroupIds(List<String> sourceApplicationSecurityGroupIds) {
		this.sourceApplicationSecurityGroupIds = sourceApplicationSecurityGroupIds;
	}
	public List<String> getSourcePortRanges() {
		return sourcePortRanges;
	}
	public void setSourcePortRanges(List<String> sourcePortRanges) {
		this.sourcePortRanges = sourcePortRanges;
	}
	public List<String> getDestinationPortRanges() {
		return destinationPortRanges;
	}
	public void setDestinationPortRanges(List<String> destinationPortRanges) {
		this.destinationPortRanges = destinationPortRanges;
	}
	public List<String> getDestinationApplicationSecurityGroupIds() {
		return destinationApplicationSecurityGroupIds;
	}
	public void setDestinationApplicationSecurityGroupIds(List<String> destinationApplicationSecurityGroupIds) {
		this.destinationApplicationSecurityGroupIds = destinationApplicationSecurityGroupIds;
	}
	public List<String> getDestinationAddressPrefixes() {
		return destinationAddressPrefixes;
	}
	public void setDestinationAddressPrefixes(List<String> destinationAddressPrefixes) {
		this.destinationAddressPrefixes = destinationAddressPrefixes;
	}

}
