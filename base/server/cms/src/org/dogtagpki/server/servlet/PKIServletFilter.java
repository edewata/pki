// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2017 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package org.dogtagpki.server.servlet;

import java.io.IOException;
import java.net.URL;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Collection;
import java.util.StringTokenizer;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.dogtagpki.rest.ServerInfoResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.cms.servlet.base.PKIService;

/**
 * @author Endi S. Dewata
 */
public class PKIServletFilter implements Filter {

    private static Logger logger = LoggerFactory.getLogger(PKIServletFilter.class);

    FilterConfig config;
    Collection<String> paths = new ArrayList<>();

    @Override
    public void init(FilterConfig config) throws ServletException {
        this.config = config;

        String value = config.getInitParameter("paths");

        if (value != null) {
            StringTokenizer st = new StringTokenizer(value, ", ");
            logger.debug("Paths:");
            while (st.hasMoreTokens()) {
                String path = st.nextToken();
                logger.debug(" - " + path);
                paths.add(path);
            }
        }
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest servletRequest = (HttpServletRequest) request;
        HttpServletResponse servletResponse = (HttpServletResponse) response;

        HttpSession session = servletRequest.getSession();

        String contextPath = servletRequest.getContextPath();
        String requestURI = servletRequest.getRequestURI();
        String path = requestURI.substring(contextPath.length());

        logger.debug("Session " + session.getId() + ": path: " + path);

        if (!paths.isEmpty() && !paths.contains(path)) {
            chain.doFilter(request, response);
            return;
        }

        String scheme = servletRequest.getScheme();
        String serverName = servletRequest.getServerName();
        int serverPort = servletRequest.getServerPort();
        URL currentURL = new URL(scheme, serverName, serverPort, contextPath + path);

        logger.debug("Session " + session.getId() + ": current URL: " + currentURL);

        URL targetURL;

        if ("https".equals(scheme)) {
            logger.debug("Session " + session.getId() + ": already on SSL connection");
            targetURL = currentURL;

        } else {
            logger.debug("Session " + session.getId() + ": non-SSL connection, redirecting to SSL");
            targetURL = new URL("https", serverName, 8443, contextPath + path);
        }

        logger.debug("Session " + session.getId() + ": target URL: " + targetURL);

        URL nextURL;

        if (PKIService.isWarningEnabled()) {

            Cookie cookie = PKIService.getCookie(servletRequest, ServerInfoResource.PKI_WARNING);

            if (cookie == null) {
                logger.debug("Session " + session.getId() + ": warning enabled but not received, redirecting to warning page");
                nextURL = new URL(scheme, serverName, serverPort,
                        "/pki/warning.jsp?next=" + URLEncoder.encode(targetURL.toString(), "UTF-8"));

            } else {
                String value = cookie.getValue();
                logger.debug("Session " + session.getId() + ": warning enabled and " + value +", redirecting to target URL");
                nextURL = targetURL;

            }

        } else {
            logger.debug("Session " + session.getId() + ": warning disabled, redirecting to target URL");
            nextURL = targetURL;
        }

        logger.debug("Session " + session.getId() + ": next URL: " + nextURL);

        if (currentURL == nextURL) {
            chain.doFilter(request, response);
        } else {
            servletResponse.sendRedirect(nextURL.toString());
        }
    }

    @Override
    public void destroy() {
    }
}
