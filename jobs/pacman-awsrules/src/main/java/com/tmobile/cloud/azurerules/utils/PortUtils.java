package com.tmobile.cloud.azurerules.utils;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import com.tmobile.pacman.commons.PacmanSdkConstants;

public class PortUtils {
	
	private PortUtils() {
		throw new IllegalStateException("Utility class");
	}
	
    /**
     * Get the common ports from given ports list
     * List can contain * or port num or port range(port1-port2)
     * @param nicPorts
     * @param subnetPorts
     * @return
     */
    public static List<String> getCommonPorts(List<String> nicPorts, List<String> subnetPorts) {
    	List<String> commonPorts = checkForAnyPorts(nicPorts, subnetPorts);
    	if(null!= commonPorts && !commonPorts.isEmpty()) {
    		return commonPorts;
    	}
    	commonPorts = new ArrayList<>();
		for(String subnetPort: subnetPorts) {
			commonPorts.addAll(getCommonPortRange(nicPorts, subnetPort));
		}
		return commonPorts;
	}

   
	/**
	 * this method does not handle * or Any ports condition
	 * @param ports
	 * @param portToCheck
	 * @return
	 */
	static List<String> getCommonPortRange(List<String> ports, String portToCheck) {
		List<String> commonPorts = new ArrayList<>();
		for(String port: ports) {
			if(port.contains(PacmanSdkConstants.HYPHEN) && portToCheck.contains(PacmanSdkConstants.HYPHEN)) {
				String overlap= getOverlappingRange(port, portToCheck);
				if(overlap!=null) {
					commonPorts.add(overlap);
				}
			} else if(port.contains(PacmanSdkConstants.HYPHEN)) {
				if(isPortInRange(Integer.valueOf(portToCheck), port)) {
					commonPorts.add(portToCheck);
				}
			} else if(portToCheck.contains(PacmanSdkConstants.HYPHEN)) {
				if(isPortInRange(Integer.valueOf(port), portToCheck)) {
					commonPorts.add(port);
				}
			} else if(portToCheck.equals(port)) {
				commonPorts.add(port);
			}
		}
		return commonPorts;
	}

	/**
	 * @param nicPorts
	 * @param subnetPorts
	 * @return
	 */
	private static List<String> checkForAnyPorts(List<String> nicPorts, List<String> subnetPorts) {
		List<String> commonPorts = null;
		if(nicPorts.contains(PacmanSdkConstants.ASTERISK) && subnetPorts.contains(PacmanSdkConstants.ASTERISK)) {
			commonPorts = new ArrayList<>();
    		commonPorts.add(PacmanSdkConstants.ASTERISK);
    		return commonPorts;
    	}
    	if(nicPorts.contains(PacmanSdkConstants.ASTERISK)) {
    		return subnetPorts;
    	}
    	if(subnetPorts.contains(PacmanSdkConstants.ASTERISK)) {
    		return nicPorts;
    	}
		return commonPorts;
	}
    
    /**
     * @param portRange1
     * @param portRange2
     * @return
     */
    public static String getOverlappingRange(String portRange1, String portRange2) {
		
		String[] portArray1 = portRange1.split(PacmanSdkConstants.HYPHEN);
		
		Integer range1Start = Integer.valueOf(portArray1[0]);
		Integer range1End = Integer.valueOf(portArray1[1]);
		
		String[] portArray2 = portRange2.split(PacmanSdkConstants.HYPHEN);
		
		Integer range2Start = Integer.valueOf(portArray2[0]);
		Integer range2End = Integer.valueOf(portArray2[1]);
							
		if(range1Start <= range2End && range2Start <= range1End) {
			Integer rangeStart = Math.max(range1Start, range2Start);
			Integer rangeEnd = Math.min(range1End, range2End);
			return (rangeStart.toString()+PacmanSdkConstants.HYPHEN+rangeEnd.toString());
		}
		return null;
	}
    
    /**
     * @param port
     * @param portRange
     * @return
     */
    public static boolean isPortInRange(Integer port, String portRange) {
		boolean isPortInRange =false;
		if(PacmanSdkConstants.ASTERISK.equals(portRange)) {
			isPortInRange = true;
		} else if(portRange.contains(PacmanSdkConstants.HYPHEN)) {
			String[] ports = portRange.split(PacmanSdkConstants.HYPHEN);
			
			Integer rangeStart = Integer.valueOf(ports[0]);
			Integer rangeEnd = Integer.valueOf(ports[1]);
								
			if(rangeStart <= port && port <= rangeEnd) {
				isPortInRange = true;
				
			}
		} else if(port.toString().equals(portRange)) {
			isPortInRange = true;
			
		}
		return isPortInRange;
	}
    
    /**
     * @param portToCheck
     * @param portRange
     * @return
     */
    public static boolean isPortInRange(String portToCheck, String portRange) {
		boolean isPortInRange =false;
		if(PacmanSdkConstants.ASTERISK.equals(portRange)) {
			isPortInRange = true;
		} else if(portToCheck.equals(portRange)) {
			isPortInRange = true;
		} else if(portRange.contains(PacmanSdkConstants.HYPHEN) && portToCheck.contains(PacmanSdkConstants.HYPHEN)) {
			String overlap= getOverlappingRange(portRange, portToCheck);
			if(overlap!=null) {
				isPortInRange = true;
			}
		} else if(portRange.contains(PacmanSdkConstants.HYPHEN)) {
			if(isPortInRange(Integer.valueOf(portToCheck), portRange)) {
				isPortInRange = true;
			}
		} else if(portToCheck.contains(PacmanSdkConstants.HYPHEN)) {
			if(isPortInRange(Integer.valueOf(portRange), portToCheck)) {
				isPortInRange = true;
			}
		} 	
		return isPortInRange;
	}
    

	/**
	 * @param port
	 * @param portRanges
	 * @return
	 */
	public static boolean containsPort(Integer port, Set<String> portRanges) {
		boolean isDestinationPort = false;
		if(port!=null && portRanges!=null) {
			for(String portRange : portRanges){
				if(isPortInRange(port, portRange)) {
					isDestinationPort =true;
					break;
				}
			}
		}
		return isDestinationPort;
	}
	
}
