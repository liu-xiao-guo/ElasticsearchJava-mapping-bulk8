import co.elastic.clients.elasticsearch.ElasticsearchAsyncClient;
import co.elastic.clients.elasticsearch.ElasticsearchClient;
import co.elastic.clients.elasticsearch._types.Refresh;
import co.elastic.clients.elasticsearch._types.mapping.TypeMapping;
import co.elastic.clients.elasticsearch.core.*;
import co.elastic.clients.elasticsearch.core.bulk.BulkResponseItem;
import co.elastic.clients.elasticsearch.indices.*;
import co.elastic.clients.json.JsonpMapper;
import co.elastic.clients.json.jackson.JacksonJsonpMapper;
import co.elastic.clients.transport.ElasticsearchTransport;
import co.elastic.clients.transport.rest_client.RestClientTransport;
import jakarta.json.Json;
import jakarta.json.stream.JsonParser;
import org.apache.http.Header;
import org.apache.http.HttpHost;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.nio.client.HttpAsyncClientBuilder;
import org.apache.http.message.BasicHeader;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.SSLContexts;
import org.elasticsearch.client.RestClient;
import org.elasticsearch.client.RestClientBuilder;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.List;

public class ElasticsearchJava {

    private static ElasticsearchClient client = null;
    private static ElasticsearchAsyncClient asyncClient = null;
    private static co.elastic.clients.elasticsearch.indices.CreateIndexResponse CreateIndexResponse;

    private static synchronized void makeConnection() {
        final CredentialsProvider credentialsProvider =
                new BasicCredentialsProvider();
        credentialsProvider.setCredentials(AuthScope.ANY,
                new UsernamePasswordCredentials("elastic", "EH3*HOpb5rmWdbDj_f4k"));

        RestClientBuilder builder = RestClient.builder(
                        new HttpHost("localhost", 9200))
                .setHttpClientConfigCallback(new RestClientBuilder.HttpClientConfigCallback() {
                    @Override
                    public HttpAsyncClientBuilder customizeHttpClient(
                            HttpAsyncClientBuilder httpClientBuilder) {
                        return httpClientBuilder
                                .setDefaultCredentialsProvider(credentialsProvider);
                    }
                });

        RestClient restClient = builder.build();

        // Create the transport with a Jackson mapper
        ElasticsearchTransport transport = new RestClientTransport(
                restClient, new JacksonJsonpMapper());

        try {
            // And create the API client
            client = new ElasticsearchClient(transport);
            asyncClient = new ElasticsearchAsyncClient(transport);
        } catch (Exception e) {
            System.out.println("Error in connecting Elasticsearch");
            e.printStackTrace();
        }
    }

    private static synchronized void makeConnection_https() throws CertificateException, IOException, NoSuchAlgorithmException,
            KeyStoreException, KeyManagementException {
        final CredentialsProvider credentialsProvider =
                new BasicCredentialsProvider();
        credentialsProvider.setCredentials(AuthScope.ANY,
                new UsernamePasswordCredentials("elastic", "FW5S2hBXhCNZDZ7BX9O-"));

        Path caCertificatePath = Paths.get("/Users/liuxg/elastic/elasticsearch-8.2.0/config/certs/http_ca.crt");
        CertificateFactory factory =
                CertificateFactory.getInstance("X.509");
        Certificate trustedCa;
        try (InputStream is = Files.newInputStream(caCertificatePath)) {
            trustedCa = factory.generateCertificate(is);
        }
        KeyStore trustStore = KeyStore.getInstance("pkcs12");
        trustStore.load(null, null);
        trustStore.setCertificateEntry("ca", trustedCa);
        SSLContextBuilder sslContextBuilder = SSLContexts.custom()
                .loadTrustMaterial(trustStore, null);
        final SSLContext sslContext = sslContextBuilder.build();

        RestClientBuilder builder = RestClient.builder(
                        new HttpHost("localhost", 9200, "https"))
                .setHttpClientConfigCallback(new RestClientBuilder.HttpClientConfigCallback() {
                    @Override
                    public HttpAsyncClientBuilder customizeHttpClient(
                            HttpAsyncClientBuilder httpClientBuilder) {
                        return httpClientBuilder.setSSLContext(sslContext)
                                .setDefaultCredentialsProvider(credentialsProvider);
                    }
                });

        RestClient restClient = builder.build();

        // Create the transport with a Jackson mapper
        ElasticsearchTransport transport = new RestClientTransport(
                restClient, new JacksonJsonpMapper());

        client = new ElasticsearchClient(transport);
        asyncClient = new ElasticsearchAsyncClient(transport);
    }

    private static synchronized void makeConnection_token() throws CertificateException, IOException, NoSuchAlgorithmException,
            KeyStoreException, KeyManagementException {
        Path caCertificatePath = Paths.get("/Users/liuxg/elastic/elasticsearch-8.2.0/config/certs/http_ca.crt");
        CertificateFactory factory =
                CertificateFactory.getInstance("X.509");
        Certificate trustedCa;
        try (InputStream is = Files.newInputStream(caCertificatePath)) {
            trustedCa = factory.generateCertificate(is);
        }
        KeyStore trustStore = KeyStore.getInstance("pkcs12");
        trustStore.load(null, null);
        trustStore.setCertificateEntry("ca", trustedCa);
        SSLContextBuilder sslContextBuilder = SSLContexts.custom()
                .loadTrustMaterial(trustStore, null);
        final SSLContext sslContext = sslContextBuilder.build();

        RestClientBuilder builder = RestClient.builder(
                        new HttpHost("localhost", 9200, "https"))
                .setHttpClientConfigCallback(new RestClientBuilder.HttpClientConfigCallback() {
                    @Override
                    public HttpAsyncClientBuilder customizeHttpClient(
                            HttpAsyncClientBuilder httpClientBuilder) {
                        return httpClientBuilder.setSSLContext(sslContext);
                    }
                });

//        String apiKeyId = "SY6uOoABwRrDJxOdlx78";
//        String apiKeySecret = "E8Ae8-FgScqT-nXCSBN0ew";
//        String apiKeyAuth =
//                Base64.getEncoder().encodeToString(
//                        (apiKeyId + ":" + apiKeySecret)
//                                .getBytes(StandardCharsets.UTF_8));
//        Header[] defaultHeaders =
//                new Header[]{new BasicHeader("Authorization",
//                        "ApiKey " + apiKeyAuth)};
//        builder.setDefaultHeaders(defaultHeaders);

        Header[] defaultHeaders =
                new Header[]{new BasicHeader("Authorization",
                        "ApiKey cUdzWVZvRUJEX1pvY2dzdnFualc6akhHX1BCRmxSME9XVlduRk1ZZUFoQQ==")};
        builder.setDefaultHeaders(defaultHeaders);

        RestClient restClient = builder.build();

        // Create the transport with a Jackson mapper
        ElasticsearchTransport transport = new RestClientTransport(
                restClient, new JacksonJsonpMapper());

        client = new ElasticsearchClient(transport);
        asyncClient = new ElasticsearchAsyncClient(transport);
    }

    public static void main(String[] args) throws IOException {
//        try {
//            makeConnection_https();
//        } catch (CertificateException e) {
//            e.printStackTrace();
//        } catch (NoSuchAlgorithmException e) {
//            e.printStackTrace();
//        } catch (KeyStoreException e) {
//            e.printStackTrace();
//        } catch (KeyManagementException e) {
//            e.printStackTrace();
//        }

        try {
            makeConnection_token();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (KeyManagementException e) {
            e.printStackTrace();
        }

        // Get the info
        InfoResponse resp = client.info();
        System.out.println(resp.version());
        System.out.println(resp.clusterName());


        ElasticsearchIndicesClient indices = client.indices();

        // Firstly remove "products" if it exists
        try {
            DeleteIndexRequest delete_request = new DeleteIndexRequest.Builder()
                    .index("products")
                    .build();
            DeleteIndexResponse delete_response = indices.delete(delete_request);
            System.out.println(delete_response.acknowledged());

        } catch (Exception e) {
            // e.printStackTrace();
        }

        // Secondly remove "test" if it exists
        try {
            DeleteIndexRequest delete_request = new DeleteIndexRequest.Builder()
                    .index("test")
                    .build();
            DeleteIndexResponse delete_response = indices.delete(delete_request);
            System.out.println(delete_response.acknowledged());

        } catch (Exception e) {
            // e.printStackTrace();
        }

        String mappingPath = System.getProperty("user.dir") + "/mappings.json";
        JsonpMapper mapper = client._transport().jsonpMapper();
        String mappings_str = new String(Files.readAllBytes(Paths.get(mappingPath)));
        System.out.println("mappings are: " +  mappings_str);
        JsonParser parser = mapper.jsonProvider()
                .createParser(new StringReader( mappings_str ));

        client.indices()
                .create(createIndexRequest -> createIndexRequest.index("test")
                        .mappings(TypeMapping._DESERIALIZER.deserialize(parser, mapper)));


        String mappings = "{\n" +
                "  \"properties\" : {\n" +
                "    \"id\" : {\n" +
                "      \"type\" : \"keyword\" \n" +
                "    },\n"+
                "    \"name\" : {\n" +
                "      \"type\" : \"text\",\n" +
                "      \"fields\" : {\n" +
                "        \"keyword\" : {\n" +
                "          \"type\" : \"keyword\",\n" +
                "          \"ignore_above\" : 256 \n" +
                "        }\n" +
                "      } \n" +
                "    }, \n" +
                "    \"price\" : { \n" +
                "      \"type\" : \"long\" \n" +
                "     } \n" +
                "  }\n" +
                "}\n";

        System.out.println( "mappings are: " + mappings );
        JsonpMapper mapper1 = client._transport().jsonpMapper();
        JsonParser parser1 = Json.createParser(new StringReader(mappings));
        CreateIndexRequest request_create =  new CreateIndexRequest.Builder()
                .index("products")
                .mappings(TypeMapping._DESERIALIZER.deserialize(parser1, mapper1))
                .build();
        CreateIndexResponse response_create = indices.create(request_create);
        System.out.println(response_create.acknowledged());

        Product prod1 = new Product("prod1", "washing machine", 42);
        Product prod2 = new Product("prod2", "TV", 42);

        List<Product> products = new ArrayList<Product>();
        products.add( prod1 );
        products.add( prod2 );

        BulkRequest.Builder br = new BulkRequest.Builder();
        for (Product product : products) {
            br.operations(op -> op
                    .index(idx -> idx
                            .index("products")
                            .id(product.getId())
                            .document(product)
                    )
            );
        }

        BulkResponse result = client.bulk(br.refresh(Refresh.WaitFor).build());

        if (result.errors()) {
            System.out.println("Bulk had errors");
            for (BulkResponseItem item: result.items()) {
                if (item.error() != null) {
                    System.out.println(item.error().reason());
                }
            }
        }

        UpdateByQueryRequest updateByQueryRequest = new UpdateByQueryRequest.Builder()
                .index("products")
                .query(q -> q
                        .match( m -> m
                                .field("id")
                                .query("prod1")
                        )
                )
                .script(s -> s.inline( src -> src
                        .lang("painless")
                        .source("ctx._source['price'] = 100")
                ))
                .build();

        UpdateByQueryResponse response_update = client.updateByQuery(updateByQueryRequest);
        System.out.println("updated : " + response_update.updated());

    }
}
