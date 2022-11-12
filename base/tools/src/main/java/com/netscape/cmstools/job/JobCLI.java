//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.job;

import java.util.Map;

import org.dogtagpki.cli.CLI;
import org.dogtagpki.job.JobClient;
import org.dogtagpki.job.JobInfo;

import com.netscape.certsrv.client.PKIClient;

/**
 * @author Endi S. Dewata
 */
public class JobCLI extends CLI {

    String prefix;
    JobClient jobClient;

    public JobCLI(CLI parent) {
        super("job", "Job management commands", parent);

        this.prefix = "rest";

        addModule(new JobFindCLI(this));
        addModule(new JobShowCLI(this));
        addModule(new JobStartCLI(this));
    }

    public JobCLI(CLI parent, String prefix) {
        super("job", "Job management commands", parent);

        this.prefix = prefix;

        addModule(new JobFindCLI(this));
        addModule(new JobShowCLI(this));
        addModule(new JobStartCLI(this));
    }

    public JobClient getJobClient() throws Exception {

        if (jobClient != null) return jobClient;

        PKIClient client = getClient();
        jobClient = new JobClient(client, parent.getName(), prefix);

        return jobClient;
    }

    public static void printJob(JobInfo jobInfo) {
        System.out.println("  Job ID: " + jobInfo.getID());
        System.out.println("  Enabled: " + jobInfo.isEnabled());

        String cron = jobInfo.getCron();
        if (cron != null) {
            System.out.println("  Cron: " + cron);
        }

        System.out.println("  Plugin: " + jobInfo.getPluginName());

        String owner = jobInfo.getOwner();
        if (owner != null) {
            System.out.println("  Owner: " + owner);
        }

        Map<String, String> params = jobInfo.getParameters();
        if (!params.isEmpty()) {
            System.out.println();
            System.out.println("  Parameters:");
            for (String name : params.keySet()) {
                String value = params.get(name);
                System.out.println("  - " + name + ": " + value);
            }
        }
    }
}
