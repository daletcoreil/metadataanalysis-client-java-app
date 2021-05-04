import com.amazonaws.HttpMethod;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.GeneratePresignedUrlRequest;
import com.amazonaws.services.s3.model.GetObjectRequest;
import com.amazonaws.services.s3.transfer.TransferManager;
import com.amazonaws.services.s3.transfer.TransferManagerBuilder;
import com.amazonaws.services.s3.transfer.Upload;
import com.dalet.mediator.metadataanalysis.*;
import com.dalet.mediator.metadataanalysis.auth.*;
import com.dalet.mediator.metadataanalysis.api.*;
import com.dalet.mediator.metadataanalysis.model.*;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicSessionCredentials;
import com.amazonaws.auth.BasicAWSCredentials;

import org.json.JSONObject;

import java.io.File;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class MetadataAnalysisClientSampleApp {
    private final String    client_id;
    private final String    client_secret;
    private final String    project_service_id;
    private final String    basePath;
    private final String    region;

    /**
     * S3 client bucket name.
     */
    private final String    bucketName;
    private final String    jsonInputKey;
    private final String    ttmlInputKey;

    private final String    folderPath;
    private final String    jsonInputFile;
    private final String    ttmlInputFile;

	private final String    dpttOutputFile;
    private final String    draftjsOutputFile;
	private final String    ttmlOutputFile;
	private final String    textOutputFile;

    private final String    dpttOutputKey;
    private final String    draftjsOutputKey;
    private final String    ttmlOutputKey;
    private final String    textOutputKey;

    private final String    aws_access_key_id;
    private final String    aws_secret_access_key;
    private final String    aws_session_token;

    private AmazonS3 s3Client;

    public static void main(String[] args) {
        try {
            MetadataAnalysisClientSampleApp impl = new MetadataAnalysisClientSampleApp(args);
            impl.run();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public MetadataAnalysisClientSampleApp(String[] args) throws Exception{
        String appConfigFile = System.getenv("APP_CONFIG_FILE");
        if (appConfigFile == null) {
            throw new ApiException("Configuration ENV file path does not exist");
        }
        Path path = Paths.get(appConfigFile);
        if (path == null) {
            throw new ApiException("Configuration file does not exist");
        }
        String data = new String(Files.readAllBytes(path));
        if(data == null) {
            throw new ApiException("Configuration file 'app-config.json' is not found in " + appConfigFile);
        }
        JSONObject config = new JSONObject(data);
        client_id = config.getString("clientKey");
        client_secret = config.getString("clientSecret");
        project_service_id = config.getString("projectServiceId");
        bucketName = config.getString("bucketName");
		region = config.has("bucketRegion") ? config.getString("bucketRegion") : "us-east-1";

        jsonInputKey = config.getString("jsonInputFile");
        ttmlInputKey = config.getString("ttmlInputFile");
        dpttOutputKey = config.getString("dpttOutputFile");
        draftjsOutputKey = config.getString("draftjsOutputFile");
		ttmlOutputKey = config.getString("ttmlOutputFile");
		textOutputKey = config.getString("textOutputFile");
        folderPath = config.getString("localPath");

		jsonInputFile       =  folderPath + jsonInputKey;
		ttmlInputFile       =  folderPath + ttmlInputKey;
		dpttOutputFile = folderPath + dpttOutputKey;
        draftjsOutputFile = folderPath + draftjsOutputKey;
		ttmlOutputFile = folderPath + ttmlOutputKey;
		textOutputFile = folderPath + textOutputKey;

        basePath = config.has("host") ? config.getString("host") : null;
		aws_access_key_id = config.has("aws_access_key_id") ? config.getString("aws_access_key_id") : null;
		aws_secret_access_key = config.has("aws_secret_access_key") ? config.getString("aws_secret_access_key") : null;
		aws_session_token = config.has("aws_session_token") ? config.getString("aws_session_token") : null;

		if(aws_secret_access_key == null || aws_access_key_id == null) {
			throw new ApiException("AWS credentials are not defined in app-config.json file");
		}
    }

    private void run() throws ApiException, InterruptedException {
        System.out.println("Starting Metadata Analysis process ...");
        // refresh auth token
        ApiClient apiClient = Configuration.getDefaultApiClient();
        if(basePath != null) {
            apiClient.setBasePath(basePath);
        }

        AuthApi authApi = new AuthApi(apiClient);
        Token token = authApi.getAccessToken(client_id, client_secret);
        System.out.println("Retrieved access token: " + token);

        ApiKeyAuth tokenSignature = (ApiKeyAuth) apiClient.getAuthentication("tokenSignature");
        tokenSignature.setApiKey(token.getAuthorization());

        MetadataAnalysisApi apiInstance = new MetadataAnalysisApi(apiClient);
        AnalyzeRequest analyzeRequest = new AnalyzeRequest()
                .text("President Donald Trump tried to explain his agitating approach to life, politics and the rest of the world in a flash of impatience during a blustery news conference in France.   " +
                        "It's the way I negotiate. " +
                        "It's done me well over the years and it's doing even better for the country, I think,  he said.")
                .extractors(Arrays.asList(
                        AnalyzeRequest.ExtractorsEnum.ENTITIES,
                        AnalyzeRequest.ExtractorsEnum.TOPICS
                ))
                .extractorsScoreThreshold(0.5)
                .classifiers(Arrays.asList(
                        AnalyzeRequest.ClassifiersEnum.IPTCNEWSCODES,
                        AnalyzeRequest.ClassifiersEnum.IPTCMEDIATOPICS
                ))
                .classifierScoreThreshold(0.5);

        AnalyzedTextResponse analyzedTextResponse = apiInstance.analyze(project_service_id, analyzeRequest);
        System.out.println(analyzedTextResponse);

        List<String> ids = analyzedTextResponse.getEntities()
                .stream()
                .filter((e) -> e.getMid() != null)
                .map((e) -> e.getMid())
                .collect(Collectors.toList());
        KnowledgeGraphSearchResponse knowledgeGraphSearchResponse = apiInstance.knowledgeGraphSearch(project_service_id, ids);
        System.out.println(knowledgeGraphSearchResponse);

        TranslateTextRequest translateTextRequest = new TranslateTextRequest()
                .text("President Donald Trump tried to explain his agitating approach to life.")
                .targetLanguage("RU");
        TranslateTextResponse translateTextResponse = apiInstance.translateText(project_service_id, translateTextRequest);
        System.out.println(translateTextResponse);

        // credentials
        initAmazonS3Client();

        // upload json file
        uploadJsonToS3();

        // prepare segment text request
		SegmentTextRequest segmentTextRequest = prepareSegmentTextRequest();

        SegmentTextResponse segmentTextResponse = apiInstance.segmentText(project_service_id, segmentTextRequest);
        System.out.println(segmentTextResponse);

        // download segment text result
        downloadSegmentResult();

        // delete segment text artifacts
        deleteS3SegmentArtifacts();

        // upload ttml file
        uploadTtmlToS3();

        // prepare translate captions request
        String targetLanguage = "RU";
        TranslateCaptionsRequest translateCaptionsRequest = prepareTranslateCaptionsRequest(targetLanguage);

        TranslateCaptionsResponse translateCaptionsResponse = apiInstance.translateCaptions(project_service_id, translateCaptionsRequest);
        System.out.println(translateCaptionsResponse);

        // download translate captions result
        downloadTranslateResult();

        // delete translate captions artifacts
        deleteS3TranslateArtifacts();

        System.out.println("Metadata Analysis process completed successfully");
    }

    private void initAmazonS3Client() {
        System.out.println("Initializing amazon S3 client ...");
        // initialize credentials ///
        //ProfileCredentialsProvider provider = new ProfileCredentialsProvider();
        //awsCredentials = provider.getCredentials();
        // init amazon client
		AWSCredentials cr;
		if(aws_session_token == null) {
			cr = new BasicAWSCredentials(aws_access_key_id, aws_secret_access_key);
		} else {
			cr = new BasicSessionCredentials(aws_access_key_id, aws_secret_access_key, aws_session_token);
		}
        s3Client = AmazonS3ClientBuilder.standard()
                .withPathStyleAccessEnabled(true)
				.withCredentials(new AWSStaticCredentialsProvider(cr))
                .withRegion(region != null ? Regions.fromName(region) : Regions.US_EAST_1)
                .build();
    }

    private void uploadJsonToS3() throws InterruptedException {
        System.out.println("Uploading json file to S3 bucket ...");
        TransferManager tm = TransferManagerBuilder.standard().withS3Client(s3Client).build();
        Upload upload = tm.upload(bucketName, jsonInputKey, new File(jsonInputFile));
        System.out.println("---****************--->"+s3Client.getUrl(bucketName, jsonInputKey).toString());
        upload.waitForCompletion();
        System.out.println("---*--->"+s3Client.getUrl(bucketName, jsonInputKey).toString());
        System.out.println("--**->"+upload.getProgress());
        System.out.println("---***--->"+s3Client.getUrl(bucketName, jsonInputKey).toString());
        System.out.println("--****->"+upload.getState());
        System.out.println("---*****--->"+s3Client.getUrl(bucketName, jsonInputKey).toString());
        System.out.println("--******->0");
        System.out.println("Object upload complete");
        System.out.println("--**********-->1");
    }

    private void uploadTtmlToS3() throws InterruptedException {
        System.out.println("Uploading ttml file to S3 bucket ...");
        TransferManager tm = TransferManagerBuilder.standard().withS3Client(s3Client).build();
        Upload upload = tm.upload(bucketName, ttmlInputKey, new File(ttmlInputFile));
        System.out.println("---****************--->"+s3Client.getUrl(bucketName, ttmlInputKey).toString());
        upload.waitForCompletion();
        System.out.println("---*--->"+s3Client.getUrl(bucketName, ttmlInputKey).toString());
        System.out.println("--**->"+upload.getProgress());
        System.out.println("---***--->"+s3Client.getUrl(bucketName, ttmlInputKey).toString());
        System.out.println("--****->"+upload.getState());
        System.out.println("---*****--->"+s3Client.getUrl(bucketName, ttmlInputKey).toString());
        System.out.println("--******->0");
        System.out.println("Object upload complete");
        System.out.println("--**********-->1");
    }

    private SegmentTextRequest prepareSegmentTextRequest() {
        // generate signed urls
        System.out.println("Generating signed URLs ...");
        String jsonInputSignedUrl = getS3PresignedUrl(bucketName, jsonInputKey,  region);
        String dpttOutputSignedUrl = generatePutSignedUrl(bucketName, dpttOutputKey,  region);
		String draftjsOutputSignedUrl = generatePutSignedUrl(bucketName, draftjsOutputKey,  region);


		System.out.println("Generated input signed URL: " + jsonInputSignedUrl);
		System.out.println("Generated output dptt signed URL: " + dpttOutputSignedUrl);
		System.out.println("Generated output draftjs signed URL: " + draftjsOutputSignedUrl);

        // segment text
        Locator jsonInputFile = new Locator()
                .awsS3Bucket(bucketName)
                .awsS3Key(jsonInputKey)
                .httpEndpoint(jsonInputSignedUrl);

        Locator draftjsFormat = new Locator()
                .awsS3Bucket(bucketName)
                .awsS3Key(draftjsOutputKey)
                .httpEndpoint(draftjsOutputSignedUrl);

        Locator dpttFormat = new Locator()
                .awsS3Bucket(bucketName)
                .awsS3Key(dpttOutputKey)
                .httpEndpoint(dpttOutputSignedUrl);

		SegmentTextResponse segmentOutputLocation = new SegmentTextResponse().dpttFile(dpttFormat).draftjsFile(draftjsFormat);

		SegmentTextRequest segmentTextRequest = new SegmentTextRequest()
                .inputFile(jsonInputFile)
                .outputLocation(segmentOutputLocation);

        return segmentTextRequest;
    }

    private TranslateCaptionsRequest prepareTranslateCaptionsRequest(String targetLanguage) {
        // generate signed urls
        System.out.println("Generating signed URLs ...");
        String ttmlInputSignedUrl = getS3PresignedUrl(bucketName, ttmlInputKey,  region);
        String ttmlOutputSignedUrl = generatePutSignedUrl(bucketName, ttmlOutputKey,  region);
		String textOutputSignedUrl = generatePutSignedUrl(bucketName, textOutputKey,  region);


		System.out.println("Generated input signed URL: " + ttmlInputSignedUrl);
		System.out.println("Generated output ttml signed URL: " + ttmlOutputSignedUrl);
		System.out.println("Generated output text signed URL: " + textOutputSignedUrl);

        // translate captions
        Locator ttmlInputFile = new Locator()
                .awsS3Bucket(bucketName)
                .awsS3Key(ttmlInputKey)
                .httpEndpoint(ttmlInputSignedUrl);

        Locator ttmlFormat = new Locator()
                .awsS3Bucket(bucketName)
                .awsS3Key(ttmlOutputKey)
                .httpEndpoint(ttmlOutputSignedUrl);

        Locator textFormat = new Locator()
                .awsS3Bucket(bucketName)
                .awsS3Key(textOutputKey)
                .httpEndpoint(textOutputSignedUrl);

		TranslateCaptionsResponse translateOutputLocation = new TranslateCaptionsResponse().ttmlFile(ttmlFormat).textFile(textFormat);

		TranslateCaptionsRequest translateCaptionsRequest = new TranslateCaptionsRequest()
                .sourceSubtitle(ttmlInputFile)
                .outputLocation(translateOutputLocation)
                .targetLanguage(targetLanguage);

        return translateCaptionsRequest;
    }

    private void deleteS3SegmentArtifacts() {
        System.out.println("Deleting artifacts from S3 ...");
        s3Client.deleteObject(bucketName, jsonInputKey);
		s3Client.deleteObject(bucketName, draftjsOutputKey);
		s3Client.deleteObject(bucketName, dpttOutputKey);
    }

    private void downloadSegmentResult() {
        System.out.println("Downloading results from S3 ...");
        File draftjsLocalFile = new File(draftjsOutputFile);
        s3Client.getObject(new GetObjectRequest(bucketName, draftjsOutputKey), draftjsLocalFile);

        File dpttLocalFile = new File(dpttOutputFile);
        s3Client.getObject(new GetObjectRequest(bucketName, dpttOutputKey), dpttLocalFile);
    }

    private void deleteS3TranslateArtifacts() {
        System.out.println("Deleting artifacts from S3 ...");
        s3Client.deleteObject(bucketName, ttmlInputKey);
		s3Client.deleteObject(bucketName, ttmlOutputKey);
		s3Client.deleteObject(bucketName, textOutputKey);
    }

    private void downloadTranslateResult() {
        System.out.println("Downloading results from S3 ...");
        File ttmlLocalFile = new File(ttmlOutputFile);
        s3Client.getObject(new GetObjectRequest(bucketName, ttmlOutputKey), ttmlLocalFile);

        File textLocalFile = new File(textOutputFile);
        s3Client.getObject(new GetObjectRequest(bucketName, textOutputKey), textLocalFile);
    }

    private  String getS3PresignedUrl(String bucket, String key,  String region) {
        java.util.Date expiration = new java.util.Date();
        long expTimeMillis = expiration.getTime();
        expTimeMillis += 1000 * 60 * 60;// Set the presigned URL to expire after one hour.
        expiration.setTime(expTimeMillis);

/*
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withPathStyleAccessEnabled(true)
                .withRegion(region != null ? Regions.fromName(region) : Regions.US_EAST_1)
                .build();
*/
		System.out.println("Generate signed URL for key: " + key);
        URL url = s3Client.generatePresignedUrl(new GeneratePresignedUrlRequest(bucket, key)
                .withMethod(HttpMethod.GET).withExpiration(expiration));
        return url.toString();
    }

    private  String generatePutSignedUrl(String bucketName, String key, String region) {
        /*
        AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                .withPathStyleAccessEnabled(true)
                //.withCredentials(new AWSStaticCredentialsProvider(new BasicAWSCredentials(awsCredentials.getAWSAccessKeyId(), awsCredentials.getAWSSecretKey())))
                .withRegion(region != null ? Regions.fromName(region) : Regions.US_EAST_1)
                .build();
        */
        // Set the pre-signed URL to expire after four hour.
        java.util.Date expiration = new java.util.Date();
        long expTimeMillis = expiration.getTime();
        expTimeMillis += 1000 * 60 * 60 * 4;
        expiration.setTime(expTimeMillis);

        // Generate the pre-signed URL.
        System.out.println("Generating pre-signed URL.");
        GeneratePresignedUrlRequest generatePresignedUrlRequest = new GeneratePresignedUrlRequest(bucketName, key)
                .withMethod(HttpMethod.PUT)
                .withExpiration(expiration);
        return s3Client.generatePresignedUrl(generatePresignedUrlRequest).toString();
    }
}
