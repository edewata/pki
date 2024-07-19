package org.dogtagpki.server.ca.rest.v2.filters;

import javax.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.SecurityDomainACL;

@WebFilter(servletNames = "caSecurityDomain")
public class CASecurityDomainACL extends SecurityDomainACL {
    private static final long serialVersionUID = 1L;
}
