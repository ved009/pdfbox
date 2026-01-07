/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.pdfbox.pdfparser;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.IOException;

import org.apache.pdfbox.Loader;
import org.junit.jupiter.api.Test;

class BruteForceParserRegressionTest
{
    @Test
    void testBruteForceMaxBytesLimit() throws IOException
    {
        String property = "pdfbox.bruteforce.maxBytes";
        File file = new File("src/test/resources/malformed/lenient_bruteforce_B_1mb.pdf");
        System.setProperty(property, "65536");
        try
        {
            IOException exception = assertThrows(IOException.class, () -> Loader.loadPDF(file));
            assertTrue(exception.getMessage().contains("pdfbox.bruteforce.maxBytes=65536"));
        }
        finally
        {
            System.clearProperty(property);
        }
    }
}
