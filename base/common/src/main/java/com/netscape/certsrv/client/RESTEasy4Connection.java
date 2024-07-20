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

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URI;
import java.net.UnknownHostException;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.ws.rs.Priorities;
import javax.ws.rs.client.WebTarget;

import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;
import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.jboss.resteasy.client.jaxrs.engines.ApacheHttpClient4Engine;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.NotInitializedException;
import org.mozilla.jss.provider.javax.crypto.JSSNativeTrustManager;
import org.mozilla.jss.ssl.SSLAlertDescription;
import org.mozilla.jss.ssl.SSLAlertEvent;
import org.mozilla.jss.ssl.SSLAlertLevel;
import org.mozilla.jss.ssl.SSLHandshakeCompletedEvent;
import org.mozilla.jss.ssl.SSLSocket;
import org.mozilla.jss.ssl.SSLSocketListener;

public class RESTEasy4Connection extends PKIConnection {

    CloseableHttpClient httpClient;

    ApacheHttpClient4Engine engine;
    javax.ws.rs.client.Client client;
    WebTarget target;

    public RESTEasy4Connection(ClientConfig config) throws Exception {

        super(config);

        //TrustStrategy acceptingTrustStrategy = (cert, authType) -> true;

        //SSLContext sslContext = SSLContexts.custom()
        //        .loadTrustMaterial(null, acceptingTrustStrategy)
        //        .build();

        SSLContext sslContext = javax.net.ssl.SSLContext.getInstance("TLS", "Mozilla-JSS");

        sslContext.init(
                KeyManagerFactory.getInstance("NssX509").getKeyManagers(),
                new TrustManager[] { new JSSNativeTrustManager() },
                null
        );

        SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(
               sslContext,
               NoopHostnameVerifier.INSTANCE);

        //SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(
        //        new JSSSocketFactory(),
        //        NoopHostnameVerifier.INSTANCE);

        Registry<ConnectionSocketFactory> socketFactoryRegistry =
                RegistryBuilder.<ConnectionSocketFactory> create()
                .register("https", sslsf)
                .register("http", new PlainConnectionSocketFactory())
                .build();

        BasicHttpClientConnectionManager connectionManager =
                new BasicHttpClientConnectionManager(socketFactoryRegistry);

        httpClient = HttpClients.custom()
                .setConnectionManager(connectionManager)
                .build();
/*
        // Register https scheme.
        Scheme scheme = new Scheme("https", 443, new JSSProtocolSocketFactory());
        httpClient.getConnectionManager().getSchemeRegistry().register(scheme);

        // Don't retry operations.
        httpClient.setHttpRequestRetryHandler(new DefaultHttpRequestRetryHandler(0, false));

        httpClient.addRequestInterceptor(new HttpRequestInterceptor() {
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

                // Set the request parameter to follow redirections.
                HttpParams params = request.getParams();
                if (params instanceof ClientParamsStack) {
                    ClientParamsStack paramsStack = (ClientParamsStack)request.getParams();
                    params = paramsStack.getRequestParams();
                }
                HttpClientParams.setRedirecting(params, true);
            }
        });

        httpClient.addResponseInterceptor(new HttpResponseInterceptor() {
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

        httpClient.setRedirectStrategy(new DefaultRedirectStrategy() {
            @Override
            public HttpUriRequest getRedirect(HttpRequest request, HttpResponse response, HttpContext context)
                    throws ProtocolException {

                HttpUriRequest uriRequest = super.getRedirect(request, response, context);

                URI uri = uriRequest.getURI();
                logger.info("HTTP redirect: "+uri);

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
*/
        engine = new ApacheHttpClient4Engine(httpClient);

        client = new ResteasyClientBuilder().httpEngine(engine).build();

        client.register(new PKIClientAuthenticator(config), Priorities.AUTHENTICATION);
        client.register(PKIRESTProvider.class);

        URI uri = config.getServerURL().toURI();
        target = client.target(uri);
    }
/*
    public void storeRequest(PrintStream out, HttpRequest request) throws IOException {

        if (request instanceof EntityEnclosingRequestWrapper) {
            EntityEnclosingRequestWrapper wrapper = (EntityEnclosingRequestWrapper) request;

            HttpEntity entity = wrapper.getEntity();
            if (entity == null)
                return;

            if (!entity.isRepeatable()) {
                BufferedHttpEntity bufferedEntity = new BufferedHttpEntity(entity);
                wrapper.setEntity(bufferedEntity);
                entity = bufferedEntity;
            }

            storeEntity(out, entity);
        }
    }

    public void storeResponse(PrintStream out, HttpResponse response) throws IOException {

        if (response instanceof BasicHttpResponse) {
            BasicHttpResponse basicResponse = (BasicHttpResponse) response;

            HttpEntity entity = basicResponse.getEntity();
            if (entity == null)
                return;

            if (!entity.isRepeatable()) {
                BufferedHttpEntity bufferedEntity = new BufferedHttpEntity(entity);
                basicResponse.setEntity(bufferedEntity);
                entity = bufferedEntity;
            }

            storeEntity(out, entity);
        }
    }

    public void storeEntity(OutputStream out, HttpEntity entity) throws IOException {

        byte[] buffer = new byte[1024];
        int c;

        try (InputStream in = entity.getContent()) {
            while ((c = in.read(buffer)) > 0) {
                out.write(buffer, 0, c);
            }
        }
    }
*/
    private class JSSSocketFactory extends SSLSocketFactory {

        @Override
        public String[] getDefaultCipherSuites() {
            return null;
        }

        @Override
        public String[] getSupportedCipherSuites() {
            return null;
        }

        @Override
        public Socket createSocket(
                Socket sock,
                String hostName,
                int port,
                boolean autoClose) throws IOException {

            // Make sure certificate database is already initialized,
            // otherwise SSLSocket will throw UnsatisfiedLinkError.
            try {
                CryptoManager.getInstance();

            } catch (NotInitializedException e) {
                throw new Error("Certificate database not initialized.", e);
            }

            SSLSocket socket;
            if (sock == null) {
                socket = new SSLSocket(InetAddress.getByName(hostName),
                        port,
                        null,
                        0,
                        callback,
                        null);

            } else {
                socker = JSSSocketFactory.createSocket();
                socket = new SSLSocket(sock, hostName, callback, null);
            }

            String certNickname = config.getCertNickname();
            if (certNickname != null) {
                logger.info("Client certificate: " + certNickname);
                socket.setClientCertNickname(certNickname);
            }

            socket.addSocketListener(new SSLSocketListener() {

                @Override
                public void alertReceived(SSLAlertEvent event) {

                    int intLevel = event.getLevel();
                    SSLAlertLevel level = SSLAlertLevel.valueOf(intLevel);

                    int intDescription = event.getDescription();
                    SSLAlertDescription description = SSLAlertDescription.valueOf(intDescription);

                    if (level == SSLAlertLevel.FATAL || logger.isInfoEnabled()) {
                        logger.error(level + ": SSL alert received: " + description);
                    }
                }

                @Override
                public void alertSent(SSLAlertEvent event) {

                    int intLevel = event.getLevel();
                    SSLAlertLevel level = SSLAlertLevel.valueOf(intLevel);

                    int intDescription = event.getDescription();
                    SSLAlertDescription description = SSLAlertDescription.valueOf(intDescription);

                    if (level == SSLAlertLevel.FATAL || logger.isInfoEnabled()) {
                        logger.error(level + ": SSL alert sent: " + description);
                    }
                }

                @Override
                public void handshakeCompleted(SSLHandshakeCompletedEvent event) {
                }

            });
            return socket;
        }

        @Override
        public Socket createSocket(String host, int port) throws IOException, UnknownHostException {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public Socket createSocket(String host, int port, InetAddress localHost, int localPort)
                throws IOException, UnknownHostException {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public Socket createSocket(InetAddress host, int port) throws IOException {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort)
                throws IOException {
            // TODO Auto-generated method stub
            return null;
        }
    }

    public WebTarget target(String path) {
        return target.path(path);
    }

    @Override
    public void close() throws Exception {
        client.close();
        engine.close();
        httpClient.close();
    }
}
