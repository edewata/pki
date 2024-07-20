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
// (C) 2015 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.certsrv.client;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.URI;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509TrustManager;
import javax.ws.rs.Priorities;
import javax.ws.rs.client.WebTarget;

import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpException;
import org.apache.http.HttpRequest;
import org.apache.http.HttpRequestInterceptor;
import org.apache.http.HttpResponse;
import org.apache.http.HttpResponseInterceptor;
import org.apache.http.ProtocolException;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.scheme.SchemeLayeredSocketFactory;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.entity.BufferedHttpEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.DefaultRedirectStrategy;
import org.apache.http.impl.client.EntityEnclosingRequestWrapper;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.client.RequestWrapper;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;
import org.apache.http.protocol.HttpContext;
import org.dogtagpki.client.NonBlockingSocketFactory;
import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.jboss.resteasy.client.jaxrs.engines.ApacheHttpClient4Engine;
import org.mozilla.jss.provider.javax.crypto.JSSKeyManager;
import org.mozilla.jss.provider.javax.crypto.JSSNativeTrustManager;
import org.mozilla.jss.ssl.SSLCertificateApprovalCallback;

public class PKIConnection implements AutoCloseable {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(PKIConnection.class);

    ClientConfig config;

    CloseableHttpClient httpClient;

    SSLCertificateApprovalCallback callback;
    SchemeLayeredSocketFactory socketFactory;

    ApacheHttpClient4Engine engine;
    javax.ws.rs.client.Client client;
    WebTarget target;

    int requestCounter;
    int responseCounter;

    File output;

    public PKIConnection(ClientConfig config) throws Exception {
        this.config = config;

        HttpClientBuilder httpClientBuilder = HttpClients.custom();

        JSSKeyManager keyManager = (JSSKeyManager) KeyManagerFactory.getInstance("NssX509").getKeyManagers()[0];

        X509TrustManager[] trustManagers = new X509TrustManager[] {
                new JSSNativeTrustManager() };

        SSLSocketFactory socketFactory = new NonBlockingSocketFactory(
                this,
                "TLS",
                keyManager,
                trustManagers);

        SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(
                socketFactory,
                NoopHostnameVerifier.INSTANCE);

        // Register http and https schemes.
        Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory> create()
                .register("http", new PlainConnectionSocketFactory())
                .register("https", sslsf)
                .build();

        BasicHttpClientConnectionManager connectionManager =
                new BasicHttpClientConnectionManager(socketFactoryRegistry);

        httpClientBuilder.setConnectionManager(connectionManager);

        // Don't retry operations.
        httpClientBuilder.disableAutomaticRetries();

        httpClientBuilder.addInterceptorFirst(new HttpRequestInterceptor() {
            @Override
            public void process(HttpRequest request, HttpContext context) throws HttpException, IOException {

                requestCounter++;

                logger.info("HTTP request: " + request.getRequestLine());
                for (Header header : request.getAllHeaders()) {
                    String name = header.getName();
                    String value = header.getValue();

                    if ("Authorization".equalsIgnoreCase(name)) {
                        value = "********";
                    }

                    logger.debug("- " + name + ": " + value);
                }

                if (output != null) {
                    File file = new File(output, "http-request-"+requestCounter);
                    try (PrintStream out = new PrintStream(file)) {
                        storeRequest(out, request);
                    }
                    logger.debug("Request: " + file.getAbsolutePath());

                } else if (logger.isDebugEnabled()) {
                    ByteArrayOutputStream os = new ByteArrayOutputStream();
                    try (PrintStream out = new PrintStream(os)) {
                        storeRequest(out, request);
                    }
                    logger.debug("Request:\n" + os.toString("UTF-8"));
                }
            }
        });

        httpClientBuilder.addInterceptorLast(new HttpResponseInterceptor() {
            @Override
            public void process(HttpResponse response, HttpContext context) throws HttpException, IOException {

                responseCounter++;

                logger.info("HTTP response: " + response.getStatusLine());
                for (Header header : response.getAllHeaders()) {
                    logger.debug("- " + header.getName() + ": " + header.getValue());
                }

                if (output != null) {
                    File file = new File(output, "http-response-"+responseCounter);
                    try (PrintStream out = new PrintStream(file)) {
                        storeResponse(out, response);
                    }
                    logger.debug("Response: " + file.getAbsolutePath());

                } else if (logger.isDebugEnabled()) {
                    ByteArrayOutputStream os = new ByteArrayOutputStream();
                    try (PrintStream out = new PrintStream(os)) {
                        storeResponse(out, response);
                    }
                    logger.debug("Response:\n" + os.toString("UTF-8"));
                }
            }
        });

        httpClientBuilder.setRedirectStrategy(new DefaultRedirectStrategy() {
            @Override
            public HttpUriRequest getRedirect(HttpRequest request, HttpResponse response, HttpContext context)
                    throws ProtocolException {

                HttpUriRequest uriRequest = super.getRedirect(request, response, context);

                URI uri = uriRequest.getURI();
                logger.info("HTTP redirect: " + uri);
                logger.info("HTTP redirect class: " + request.getClass());

                // Redirect the original request to the new URI.
                RequestWrapper wrapper;
                if (request instanceof HttpEntityEnclosingRequest) {
                    wrapper = new EntityEnclosingRequestWrapper((HttpEntityEnclosingRequest)request);
                } else {
                    wrapper = new RequestWrapper(request);
                }
                wrapper.setURI(uri);

                return wrapper;
            }

            @Override
            public boolean isRedirected(HttpRequest request, HttpResponse response, HttpContext context)
                    throws ProtocolException {

                // The default redirection policy does not redirect POST or PUT.
                // This overrides the policy to follow redirections for all HTTP methods.
                return response.getStatusLine().getStatusCode() == 302;
            }
        });

        httpClient = httpClientBuilder.build();
        engine = new ApacheHttpClient4Engine(httpClient);

        client = new ResteasyClientBuilder().httpEngine(engine).build();

        client.register(new PKIClientAuthenticator(config), Priorities.AUTHENTICATION);
        client.register(PKIRESTProvider.class);

        URI uri = config.getServerURL().toURI();
        target = client.target(uri);
    }

    public ClientConfig getConfig() {
        return config;
    }

    public SSLCertificateApprovalCallback getCallback() {
        return callback;
    }

    public void setCallback(SSLCertificateApprovalCallback callback) {
        this.callback = callback;
    }

    public void storeRequest(PrintStream out, HttpRequest request) throws IOException {

        logger.info("Request class: " + request.getClass());

        if (request instanceof HttpPost postRequest) {
            HttpEntity entity = postRequest.getEntity();

            if (entity == null)
                return;

            if (!entity.isRepeatable()) {
                // store entity into a buffer and put it back into request
                BufferedHttpEntity bufferedEntity = new BufferedHttpEntity(entity);
                postRequest.setEntity(bufferedEntity);
                entity = bufferedEntity;
            }

            //storeEntity(out, entity);

            byte[] buffer = new byte[1024];
            int c;

            try (InputStream in = entity.getContent()) {
                while ((c = in.read(buffer)) > 0) {
                    logger.info("Writing request: " + c + " bytes");
                    out.write(buffer, 0, c);
                }
            }
        }
    }

    public void storeResponse(PrintStream out, HttpResponse response) throws IOException {

        logger.info("Response class: " + response.getClass());

        HttpEntity entity = response.getEntity();
        if (entity == null)
            return;

        if (!entity.isRepeatable()) {
            // store entity into a buffer and put it back into response
            BufferedHttpEntity bufferedEntity = new BufferedHttpEntity(entity);
            response.setEntity(bufferedEntity);
            entity = bufferedEntity;
        }

        //storeEntity(out, entity);

        byte[] buffer = new byte[1024];
        int c;

        try (InputStream in = entity.getContent()) {
            while ((c = in.read(buffer)) > 0) {
                logger.info("Writing response: " + c + " bytes");
                out.write(buffer, 0, c);
            }
        }
    }

    public void storeEntity(OutputStream out, HttpEntity entity) throws IOException {

        byte[] buffer = new byte[1024];
        int c;

        try (InputStream in = entity.getContent()) {
            while ((c = in.read(buffer)) > 0) {
                logger.info("Writing " + c + " bytes");
                out.write(buffer, 0, c);
            }
        }
    }

    public WebTarget target(String path) {
        return target.path(path);
    }

    public File getOutput() {
        return output;
    }

    public void setOutput(File output) {
        this.output = output;
    }

    @Override
    public void close() throws Exception {
        client.close();
        engine.close();
        httpClient.close();
    }
}
