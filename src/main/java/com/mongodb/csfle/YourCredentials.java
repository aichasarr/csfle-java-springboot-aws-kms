package com.mongodb.csfle;
/*
 * Copyright 2008-present MongoDB, Inc.

 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

public class YourCredentials {
    private static Map<String, String> yourCredentials;
    static {
        yourCredentials = new HashMap<>();
        // Mongo Paths + URI
        yourCredentials.put("MONGODB_URI", "mongodb://localhost:27017");
        //yourCredentials.put("MONGOCRYPTD_PATH", "/usr/local/bin");
        yourCredentials.put("MONGOCRYPTD_URL", "mongodb://localhost:27020");
        // AWS Credentials
        yourCredentials.put("AWS_ACCESS_KEY_ID", "AKIA6IESFAOZZTC6S3BS");
        yourCredentials.put("AWS_SECRET_ACCESS_KEY", "1g5CkyTAhbaDkD91ii/jV8cUikhSAgwGaIzTwSFN");
        yourCredentials.put("AWS_KEY_REGION", "eu-west-3");
        yourCredentials.put("AWS_KEY_ARN", "arn:aws:kms:eu-west-3:979559056307:key/f8e7ed74-4801-480c-8292-f2bd821322da");

    }
    private static void checkPlaceholders() throws Exception {
        Pattern p = Pattern.compile("<.*>$");
        ArrayList<String> errorBuffer = new ArrayList<String>();
        for (Map.Entry<String,String> entry : yourCredentials.entrySet()) {
            if(p.matcher(String.valueOf(entry.getValue())).matches()){
                String message = String.format("The value for %s is empty. Please enter something for this value.", entry.getKey());
                errorBuffer.add(message);
            }
        }
        if (!errorBuffer.isEmpty()){
            String message = String.join("\n", errorBuffer);
            throw new Exception(message);
        }
    }
    public static Map<String, String> getCredentials() throws Exception {
        checkPlaceholders();
        return yourCredentials;
    }
}
