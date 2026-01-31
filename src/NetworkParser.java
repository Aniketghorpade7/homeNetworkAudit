import java.io.*;
import java.util.*;
import java.util.regex.*;

public class NetworkParser {
    public static void main(String[] args) throws Exception{
        
        // BufferReader to read the input from file
        BufferedReader read = new BufferedReader(new FileReader("../scans/output.txt"));
        List<String> ips = new ArrayList<>();

        Pattern ipPattern = Pattern.compile("\\b\\d{1,3}(\\.\\d{1,3}){3}\\b");

        String line;
        while((line = read.readLine()) != null){
            Matcher matcher = ipPattern.matcher(line);

            while(matcher.find()){
                ips.add(matcher.group());
            }
        }

        read.close();

        for(String ip : ips){
            System.out.println(ip);
        }
    }
}
