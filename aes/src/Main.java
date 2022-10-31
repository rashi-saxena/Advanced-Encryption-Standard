// AES Round 1 Encryption

import java.io.*;
import java.util.Scanner;

public class Main {

    static int sbox[][] = {{0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76}, {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0}, {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15}, {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75}, {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84}, {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf}, {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8}, {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2}, {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73}, {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb}, {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79}, {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08}, {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a}, {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e}, {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf}, {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}};
    static int micColArr[][] = {{0x2, 0x3, 0x1, 0x1}, {0x1, 0x2, 0x3, 0x1}, {0x1, 0x1, 0x2, 0x3}, {0x3, 0x1, 0x1, 0x2}};
    static int subkey0[][] = new int[4][4];

    public static void main(String[] args) {

        // Reading message from file data/plaintext.txt
        String plaintext = readTextFromFile();
        System.out.println("plaintext: "+plaintext);

        // Creating Initial State
        int initialState[][] = new int[4][4];
        int j = 0, k = 0;
        if(plaintext != null) {
            for (int i = 0; i < plaintext.length(); i++) {
                initialState[j][k] = plaintext.charAt(i);
                if(j<3) {
                    j++;
                } else if(j == 3) {
                    k++;
                    j = 0;
                }
            }
        }
        System.out.println();

        // print initial state
        System.out.println("Initial State:");
        for(int z=0; z<4; z++) {
            for(int y=0; y<4; y++) {
                System.out.print(Integer.toHexString(initialState[z][y])+" ");
            }
            System.out.println();
        }
        System.out.println();

        // generating subkey0 and subkey1
        int subkey1[][] = subkeyGeneration();

        // AddKey before Round 1 - initialState XOR subkey0
        int addKeyResult[][] = addkey(initialState, subkey0);
        System.out.println("Add key:");
        for(int i=0; i<4; i++) {
            for(int p=0; p<4; p++) {
                System.out.print(Integer.toHexString(addKeyResult[i][p])+" ");
            }
            System.out.println();
        }
        System.out.println();

        /////////// ROUND 1 /////////////

        System.out.println("AES Round 1");

        // Step1: SubBytes
        int subBytesResult[][] = subBytes(addKeyResult);
        System.out.println("\nSubbytes:");
        for(int i=0; i<4; i++) {
            for(int p=0; p<4; p++) {
                System.out.print(Integer.toHexString(subBytesResult[i][p])+" ");
            }
            System.out.println();
        }
        System.out.println();

        // Step2: ShiftRows
        int shiftRowsResult[][] = shiftRows(subBytesResult);
        System.out.println("\nShift Rows:");
        for(int i=0; i<4; i++) {
            for(int p=0; p<4; p++) {
                System.out.print(Integer.toHexString(shiftRowsResult[i][p])+" ");
            }
            System.out.println();
        }
        System.out.println();

        // Step3: MixColumns
        int mixColumnResult[][] = mixColumn(shiftRowsResult);
        System.out.println("\nMix Column:");
        for(int i=0; i<4; i++) {
            for(int p=0; p<4; p++) {
                System.out.print(Integer.toHexString(mixColumnResult[i][p])+" ");
            }
            System.out.println();
        }
        System.out.println();

        // Step4: AddKey
        String resultRound1 = "0x";
        int addKeyResult2[][] = addkey(mixColumnResult, subkey1);
        System.out.println("\nAdd key:");
        for(int i=0; i<4; i++) {
            for(int p=0; p<4; p++) {
                if(Integer.toHexString(addKeyResult2[i][p]).length() < 2) {
                    System.out.print("0"+Integer.toHexString(addKeyResult2[i][p])+" ");
                } else {
                    System.out.print(Integer.toHexString(addKeyResult2[i][p]) + " ");
                }
                if(Integer.toHexString(addKeyResult2[p][i]).length() < 2) {
                    resultRound1 = resultRound1.concat("0");
                }
                resultRound1 = resultRound1.concat(Integer.toHexString(addKeyResult2[p][i]));
            }
            System.out.println();
        }
        System.out.println();

        // Writing Result of Round1 Encryption to data/result.txt
        System.out.println("\nAES Round 1 Encryption Result: "+resultRound1);
        try {
            File result = new File("../data/result.txt");
            FileWriter resultWriter = new FileWriter("../data/result.txt");
            resultWriter.write(resultRound1.toString());
            resultWriter.close();
        } catch (IOException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
        }

    }

    /*
    method: readTextFromFile
    input: null
    output: plaintext(String)
    desc.: reads the plaintext message from plaintext.txt
     */
    public static String readTextFromFile() {
        String plaintext = null;
        try {
            //File fis = new File("C:\\Users\\hp\\Desktop\\UC Assignment\\Network Security\\Project 1\\aes_m14514088\\data\\input.txt");
            File fis = new File("../data/plaintext.txt");
            Scanner fileSc = new Scanner(fis);
            if(fileSc.hasNextLine()) {
                plaintext = fileSc.nextLine();
            }
            fileSc.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        return plaintext;
    }

    /*
    method: subkeyGeneration
    input: null
    output: subkey1(2-D int array)
    desc.: generates subkey0 and subkey1 from the encryption key and store it in the result_subkey.txt file
     */
    public static int[][] subkeyGeneration() {

        int w03[][] = new int[4][4];
        int w47[][] = new int[4][4];
        int gw3[] = new int[4];
        int w3Subbytes[] = new int[4];
        String encryptionKey = null;

        // Read encryption key from Subkey_example text file
        try {
            //File fis = new File("C:\\Users\\hp\\Desktop\\UC Assignment\\Network Security\\Project 1\\aes_m14514088\\data\\subkey_example.txt");
            File fis = new File("../data/subkey_example.txt");
            Scanner fileSc = new Scanner(fis);
            if(fileSc.hasNextLine()) {
                encryptionKey = fileSc.nextLine();
            }
            fileSc.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        System.out.println("\nEncryption key: "+encryptionKey);
        System.out.println();
        if(encryptionKey == null || encryptionKey.length() != 34) {
            System.out.println("Incorrect Encryption Key!!");
        } else {
            int j = 0, k = 0;
            System.out.println("\nSubkey 0:");
            for(int i=2; i<33; i+=2) {
                subkey0[j][k] = Integer.parseInt(encryptionKey.substring(i,i+2),16);
                System.out.print(Integer.toHexString(subkey0[j][k])+" ");
                if(j<3) {
                    j++;
                } else if(j == 3) {
                    System.out.println();
                    k++;
                    j = 0;
                }
            }

        }
        System.out.println();

        for(int i=0; i<4; i++) {
            for(int j=0; j<4; j++) {
                w03[i][j] = subkey0[j][i];
            }
        }

        // compute g(w3)
        gw3 = shiftEachRow(w03[3], 1);

        // compute subbytes
        for(int i=0; i<4; i++) {
            w3Subbytes[i] = computeSboxOutput(gw3[i]);
        }

        // xor subbytes with round constant 1
        w3Subbytes[0] = w3Subbytes[0] ^ 0x01;

        // w4 generation: w4 = w0 xor gw3
        for(int i=0; i<4; i++) {
            w47[0][i] = subkey0[i][0] ^ w3Subbytes[i];
        }

        // w5-7 generation
        for(int i=1; i<4; i++) {
            for(int j=0; j<4; j++) {
                w47[i][j] = w47[i-1][j] ^ w03[i][j];
            }
        }

        // print subkey1
        String subkey1str = "0x";
        for(int i=0; i<4; i++) {
            for(int j=0; j<4; j++) {
                if((Integer.toHexString(w47[i][j]).length() < 2)) {
                    subkey1str = subkey1str.concat("0");
                }
                subkey1str = subkey1str.concat(Integer.toHexString(w47[i][j]));
            }
        }

        int subkey1[][] = new int[4][4];
        int j = 0, k = 0;
        for(int i=2; i<33; i+=2) {
            subkey1[j][k] = Integer.parseInt(subkey1str.substring(i,i+2),16);
            if(j<3) {
                j++;
            } else if(j == 3) {
                k++;
                j = 0;
            }
        }
        // Writing Subkey 1 to /data/result_subkey.txt
        System.out.println("Subkey 1: "+subkey1str);
        try {
            File subkey1File = new File("../data/result_subkey.txt");
            FileWriter subkey1Writer = new FileWriter("../data/result_subkey.txt");
            subkey1Writer.write(subkey1str);
            subkey1Writer.close();
        } catch (IOException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
        }
        System.out.println();

        return subkey1;
    }

    /*
    method: shiftRows
    input: Output of Step1 SubBytes(2-D int array)
    output: Output of Step2 ShiftRows
    desc.: shifts byte in state
     */
    public static int[][] shiftRows(int subBytesResult[][]) {
        int shiftRowResult[][] = new int[4][4];
        for(int i=0; i<4; i++) {
            shiftRowResult[i] = shiftEachRow(subBytesResult[i], i);
        }
        return  shiftRowResult;
    }

    /*
    method: shiftEachRow
    input: Array to shift(str), and shift by(int)
    output: shifted array
    desc.: shifts array str left by shiftBy times
     */
    public static int[] shiftEachRow(int[] str, int shiftBy){
        int newStr[] = new int[str.length];
        int strLength = str.length;
        for(int i = 0; i < strLength; i++){
            newStr[i] = str[(i+shiftBy)%strLength];
        }
        return newStr;
    }

    /*
    method: subBytes
    input: Result of first AddKey
    output: Output of step1 SubBytes
    desc.: store AES S-Box values
     */
    public static int[][] subBytes(int addKeyResult[][]) {
        int subBytesResult[][] = new int[4][4];
        for(int i=0; i<4; i++) {
            for(int j=0; j<4; j++) {
                subBytesResult[i][j] = computeSboxOutput(addKeyResult[i][j]);
            }
        }
        return subBytesResult;
    }

    /*
    method: computeSboxOutput
    input: input for AES S-Box(int)
    output: Output of AES S-Box(int)
    desc.: Calculates the output for AES S-Box
     */
    public static int computeSboxOutput(int input) {
        int r = 0, c = 0;
        String ip = Integer.toHexString(input);
        if(ip.length() != 2) {
            ip = "0" + ip;
        }
        for(int i=0; i<2; i++) {
            int t = 0;
            if(ip.charAt(i) == 'a') {
                t = 10;
            } else if(ip.charAt(i) == 'b') {
                t = 11;
            } else if(ip.charAt(i) == 'c') {
                t = 12;
            } else if(ip.charAt(i) == 'd') {
                t = 13;
            } else if(ip.charAt(i) == 'e') {
                t = 14;
            } else if(ip.charAt(i) == 'f') {
                t = 15;
            } else {
                t = Character.getNumericValue(ip.charAt(i));
            }
            if(i == 0) {
                r = t;
            }
            if(i == 1) {
                c = t;
            }
        }
        return sbox[r][c];
    }

    /*
    method: addkey
    input: State and Subkey
    output: Output of AddKey
    desc.: performs XOR of State and Subkey
     */
    public static int[][] addkey(int state[][], int subkey[][]) {
        int addKeyResult[][] = new int[4][4];
        for(int i=0; i<4; i++) {
            for(int j=0; j<4; j++) {
                addKeyResult[i][j] = state[i][j] ^ subkey[i][j];
            }
        }
        return addKeyResult;
    }

    /*
    method: mixColumn
    input: Result of step2 ShiftRows
    output: Output of step3 MixColumns
    desc.: calculate the value of MixColumn
     */
    public static int[][] mixColumn(int shiftRowsResult[][]) {
        int mixColumnResult[][] = new int[4][4];
        for(int i=0; i<4; i++) {
            for(int j=0; j<4; j++) {
                int ans = 0;
                for(int k=0; k<4; k++) {
                    ans = ans ^ mixColMul(micColArr[i][k], shiftRowsResult[k][j]);
                }
                mixColumnResult[i][j] = ans;
            }
        }
        return mixColumnResult;
    }

    /*
    method: mixColMul
    input: two numbers
    output: multiplication for mixcolumn
    desc.: performs multiplication operation for MixColumn
     */
    public static int mixColMul(int num1, int num2) {
        int ans = 0;
        if(num1 == 1) {
            ans = num2;
        } else if(num1 == 2) {
            String num2Binary = Integer.toBinaryString(num2);
            if(num2Binary.charAt(0) == '0') {
                ans = num2 * 2;
            } else if(num2Binary.charAt(0) == '1') {
                ans = (num2 * 2) ^ 27;
            }
        } else if(num1 == 3) {
            String num2Binary = Integer.toBinaryString(num2);
            if(num2Binary.charAt(0) == '0') {
                ans = num2 * 2;
            } else if(num2Binary.charAt(0) == '1') {
                ans = (num2 * 2) ^ 27;
            }
            ans = ans^num2;
        }
        if(ans > 0xff) {
            ans = ans ^ 0x11b;
        }
        return ans;
    }
}
