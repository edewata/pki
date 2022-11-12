//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.server;

import java.security.Principal;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.ForbiddenException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.dogtagpki.job.JobCollection;
import org.dogtagpki.job.JobInfo;
import org.dogtagpki.job.JobResource;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.ResourceNotFoundException;
import com.netscape.cms.realm.PKIPrincipal;
import com.netscape.cmscore.jobs.JobConfig;
import com.netscape.cmscore.jobs.JobsConfig;

/**
 * @author Endi S. Dewata
 */
public class ACMEJobService implements JobResource {

    public static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ACMEJobService.class);

    @Context
    protected HttpServletRequest servletRequest;

    boolean isAdmin(Principal principal) {

        if (principal instanceof PKIPrincipal pkiPrincipal) {
            List<String> roles = Arrays.asList(pkiPrincipal.getRoles());
            return roles.contains("Administrators");
        }

        return false;
    }

    boolean isOwner(Principal principal, JobConfig jobConfig) throws EBaseException {

        if (principal == null) {
            return false;
        }

        String username = principal.getName();
        String owner = jobConfig.getOwner(); // can be null

        return username.equals(owner);
    }

    public JobInfo createJobInfo(String id, JobConfig jobConfig, boolean includeDetails) throws EBaseException {

        JobInfo jobInfo = new JobInfo();
        jobInfo.setID(id);

        // store the following config params as fields
        jobInfo.setEnabled(jobConfig.isEnabled());
        jobInfo.setCron(jobConfig.getCron());
        jobInfo.setPluginName(jobConfig.getPluginName());
        jobInfo.setOwner(jobConfig.getOwner());

        if (!includeDetails) {
            return jobInfo;
        }

        // store the remaining config params
        Map<String, String> properties = jobConfig.getProperties();
        for (String name : properties.keySet()) {

            if (name.equals("enabled")) continue;
            if (name.equals("cron")) continue;
            if (name.equals("pluginName")) continue;

            String value = properties.get(name);
            jobInfo.setParameter(name, value);
        }

        return jobInfo;
    }

    @Override
    public Response findJobs() throws EBaseException {

        logger.info("ACMEJobService: Finding jobs");

        JobCollection response = new JobCollection();

        ACMEEngine engine = ACMEEngine.getInstance();
        JobsConfig jobsConfig = engine.getJobsConfig();

        Principal principal = servletRequest.getUserPrincipal();
        logger.info("ACMEJobService: - principal: " + principal);

        boolean isAdmin = isAdmin(principal);

        logger.info("ACMEJobService: - jobs:");
        Enumeration<String> list = jobsConfig.getSubStoreNames().elements();
        while (list.hasMoreElements()) {
            String id = list.nextElement();
            logger.info("ACMEJobService:   - " + id);

            JobConfig jobConfig = jobsConfig.getJobConfig(id);

            boolean isOwner = isOwner(principal, jobConfig);
            if (!isAdmin && !isOwner) {
                continue;
            }

            JobInfo jobInfo = createJobInfo(id, jobConfig, false);
            response.addEntry(jobInfo);
        }

        return Response
                .ok(response)
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
    }

    @Override
    public Response getJob(String id) throws EBaseException {

        logger.info("ACMEJobService: Getting job " + id);

        ACMEEngine engine = ACMEEngine.getInstance();
        JobsConfig jobsConfig = engine.getJobsConfig();

        JobConfig jobConfig = jobsConfig.getJobConfig(id);

        if (jobConfig == null) {
            throw new ResourceNotFoundException("Job " + id + " not found");
        }

        Principal principal = servletRequest.getUserPrincipal();
        logger.info("ACMEJobService: - principal: " + principal);

        boolean isAdmin = isAdmin(principal);
        boolean isOwner = isOwner(principal, jobConfig);

        if (!isAdmin && !isOwner) {
            throw new ForbiddenException();
        }

        JobInfo jobInfo = createJobInfo(id, jobConfig, true);

        return Response
                .ok(jobInfo)
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
    }

    @Override
    public Response startJob(String id) throws EBaseException {

        logger.info("ACMEJobService: Starting job " + id);

        ACMEEngine engine = ACMEEngine.getInstance();
        JobsConfig jobsConfig = engine.getJobsConfig();

        JobConfig jobConfig = jobsConfig.getJobConfig(id);

        if (jobConfig == null) {
            throw new ResourceNotFoundException("Job " + id + " not found");
        }

        Principal principal = servletRequest.getUserPrincipal();
        logger.info("ACMEJobService: - principal: " + principal);

        boolean isAdmin = isAdmin(principal);
        boolean isOwner = isOwner(principal, jobConfig);

        if (!isAdmin && !isOwner) {
            throw new ForbiddenException();
        }

        //JobsScheduler jobsScheduler = null;
        //jobsScheduler.startJob(id);

        return Response
                .ok()
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
    }
}
