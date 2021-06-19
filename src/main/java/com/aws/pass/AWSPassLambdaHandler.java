package com.aws.pass;

import java.util.Map;
import java.util.UUID;

import com.amazonaws.regions.Region;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClient;
import com.amazonaws.services.dynamodbv2.document.DynamoDB;
import com.amazonaws.services.dynamodbv2.document.Item;
import com.amazonaws.services.dynamodbv2.document.PutItemOutcome;
import com.amazonaws.services.dynamodbv2.document.spec.PutItemSpec;
import com.amazonaws.services.dynamodbv2.model.ConditionalCheckFailedException;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.LambdaLogger;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.aws.pass.encrypt.EncryptionException;
import com.aws.pass.encrypt.EncryptionUtil;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

public class AWSPassLambdaHandler implements RequestHandler<Map<String, String>, String> {
	Gson gson = new GsonBuilder().setPrettyPrinting().create();
	private DynamoDB dynamoDb;
	private String DYNAMODB_TABLE_NAME = "credentials";
	private Regions REGION = Regions.US_EAST_2;

	@Override
	public String handleRequest(Map<String, String> data, Context context) {
		LambdaLogger logger = context.getLogger();
		logger.log("CONTEXT: " + gson.toJson(context));
		String key = System.getenv("encryption_key");
		try {
			String encryptedPassword = EncryptionUtil.encrypt(key, data.get("password"));
			String username = data.get("username");
			String url = data.get("url");
			this.initDynamoDbClient();
			persistData(username, encryptedPassword, url);
		} catch (EncryptionException e) {
			return "Exception occurred: " + e;
		}
		return "data saved successfully in DB";
	}

	private PutItemOutcome persistData(String username, String password, String url)
			throws ConditionalCheckFailedException {
		return this.dynamoDb
				.getTable(DYNAMODB_TABLE_NAME)
				.putItem(new PutItemSpec()
						.withItem(new Item()
								.withString("id", UUID.randomUUID().toString())
								.withString("username", username)
								.withString("password", password)
								.withString("url", url)));
	}

	@SuppressWarnings("deprecation")
	private void initDynamoDbClient() {
		AmazonDynamoDBClient client = new AmazonDynamoDBClient();
		client.setRegion(Region.getRegion(REGION));
		this.dynamoDb = new DynamoDB(client);
	}
}