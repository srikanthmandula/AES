import java.util.*;
import java.io.*;
import java.math.*;

public class AES {

	int[] mdeg= new int[9];

	int pr=2;

	int[][] sbox_encry_matrix = 
			{	
			{1,0,0,0,1,1,1,1},
			{1,1,0,0,0,1,1,1},
			{1,1,1,0,0,0,1,1},
			{1,1,1,1,0,0,0,1},
			{1,1,1,1,1,0,0,0},
			{0,1,1,1,1,1,0,0},
			{0,0,1,1,1,1,1,0},
			{0,0,0,1,1,1,1,1}}, 
			
		sbox_decry_matrix={
		{0,0,1,0,0,1,0,1},
		{1,0,0,1,0,0,1,0},
		{0,1,0,0,1,0,0,1},
		{1,0,1,0,0,1,0,0},
		{0,1,0,1,0,0,1,0},
		{0,0,1,0,1,0,0,1},
		{1,0,0,1,0,1,0,0},
		{0,1,0,0,1,0,1,0}
		};

	String[][] shift_col_encry_vals = {{"02","03","01","01"},{"01","02","03","01"},{"01","01","02","03"},{"03","01","01","02"}};
	String[][]shift_col_decry_vals = {
		{"0e","0b","0d","09"},
		{"09","0e","0b","0d"},
		{"0d","09","0e","0b"},
		{"0b","0d","09","0e"}};
		
	int[] const_col_encry_vals = {1,1,0,0,0,1,1,0},const_col_decry_vals = {1,0,1,0,0,0,0,0};
	String[] rouund_constants= {"01","02","04","08","10","20","40","80","1b","36"};
	Object[][][] keys1,keys2;

	public AES()
	{
	//System.out.println();
	//System.out.println( " Performing AES encryption and Decryption");
	//System.out.println();
	}


	public static void main(String[] args) throws IOException
	{ 
		AES AES_Implementation = new AES();
		AES_Implementation.inputFile();
	}

	public void inputFile()
	{
		String[] inputLines=read_file_input();
		String str = inputLines[0].replaceAll("\\s", "");
		for(int i=0;i<9;i++)
			mdeg[i]=Integer.parseInt(""+str.charAt(i));

		number_system_workings();
		String key_value = inputLines[1];
		String plaint_text =inputLines[2];
		Object[][] key_first = transform_to_state(key_value); 
		Object[][] key_decry = transform_to_state(key_value);
		Object[][] inputState = transform_to_state(plaint_text);
		keys1 = on_key_workings(key_first);
		keys2 = on_key_workings(key_first);

		String cipherText = encryption_AES(key_first,inputState);
	//	System.out.println();
		
		//System.out.println("Input plaintext is      -  " + plaint_text);
		//System.out.println("Input encrypted text is -  " + cipherText);
		//System.out.println();
		//System.out.println();
		

		String plaintext = decryption(inputLines[3],key_decry);
		//System.out.println("Given encrypted text is - " + inputLines[3]);
		//System.out.println("Given plaintext is      - " + plaintext);

		printOutputFile(cipherText,plaintext);	
	}


	public void number_system_workings() {
		int[] temp_obj = convert_hex_to_binary("02");

		rouund_constants[0] = "01";
		for (int j = 1; j < 10; j++) {
			int[] Rc = multiplicate(temp_obj, convert_hex_to_binary(rouund_constants[j-1]), false);
			rouund_constants[j] = convert_binary_to_hex(Rc);
		}

		
	}

	
	public void printOutputFile(String ciphertext,String key_first){
		try 
		{
			PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter("Output.txt")));
			out.println(ciphertext);
			out.println(key_first);
			out.close();
		} catch (IOException e) 
		{
			e.printStackTrace();
		}
	}
	
	public String[] read_file_input(){
		String[] lines = new String[4];
		try{
			BufferedReader plaint_text = new BufferedReader(new FileReader("Input.txt"));
			for(int i=0; i<4;i++)
				lines[i]=plaint_text.readLine();
		}
		catch(IOException e)
		{
			e.printStackTrace();
		} 
		return lines;
	}

	
	public String encryption_AES(Object[][] key_first, Object[][] inputState){
		//System.out.println("Encrypting: " + transform_state_to_string(key_first));
		Object[][] present_state = add_round_key(key_first, inputState);
		for(int i=0;i<9;i++){
			//System.out.println("Result from Round : " + i);
			//System.out.println("  Input  value : " + transform_state_to_string(present_state));
			present_state = substitutionBytes(present_state);
			present_state = shift_rows(present_state);
			present_state = mix_columns(present_state);
			present_state = add_round_key(present_state,keys1[i]);
			//System.out.println("  Output value:  " + transform_state_to_string(present_state));
			//System.out.println();
		}
		present_state=substitutionBytes(present_state);
		present_state=shift_rows(present_state);
		present_state=add_round_key(present_state,keys1[9]);
		present_state = elimininate_zeros(present_state);
		String string2 = transform_state_to_string(present_state);
		return string2;
	}

	
	public String decryption(String cipher_text,Object[][] key_decry){
		Object[][] present_state = transform_to_state(cipher_text);
		present_state = add_round_key(keys1[9],present_state);
		for(int i=8;i>=0;i--){
			present_state=inverse_shft_rows(present_state);
			present_state=inverse_substitution_bytes(present_state);
			present_state=add_round_key(present_state,keys2[i]);	
			present_state=inverse_mix_columns(present_state);
		}
		present_state = inverse_shft_rows(present_state);
		present_state = inverse_substitution_bytes(present_state);
		present_state = add_round_key(present_state,key_decry);
		present_state = elimininate_zeros(present_state);
		String string3 = transform_state_to_string(present_state); 
		return string3;
	}

	
	public Object[][] inverse_shft_rows(Object[][]temp_obj){
		Object temp = temp_obj[3][1];
		for(int i=3;i>0;i--)
			temp_obj[i][1]=temp_obj[i-1][1];
		temp_obj[0][1]=temp;
		for(int j=0;j<2;j++){
			Object temp_1 = temp_obj[3][2];
			for(int i=3;i>0;i--)
				temp_obj[i][2]=temp_obj[i-1][2];
			temp_obj[0][2]=temp_1;
		}
		for(int j=0;j<3;j++){
			Object temp_1 = temp_obj[3][3];
			for(int i=3;i>0;i--)
				temp_obj[i][3]=temp_obj[i-1][3];
			temp_obj[0][3]=temp_1;
		}
		return temp_obj;
	}

	
	public Object[][] add_round_key(Object[][]temp_obj,Object[][]temp_obj2){
		Object[][] r1 = new Object[4][4];
		for(int col=0;col<4;col++){
			for(int i=0;i<4;i++){
				int[] x = standardization(convert_hex_to_binary((String)temp_obj[col][i]),8);
				int[] y = standardization(convert_hex_to_binary((String)temp_obj2[col][i]),8);
				int[] add = standardization(Add(x, y, false),8);
				String string3 = convert_binary_to_hex(add);
				r1[col][i]=string3 ;
			}
		}
		return r1;
	}

	
	public Object[][] shift_rows(Object[][]temp_obj){	
		Object t = temp_obj[0][1];
		for(int i=0;i<3;i++)
			temp_obj[i][1]=temp_obj[i+1][1];
		temp_obj[3][1]=t;
		for(int j=0;j<2;j++){
			Object t1 = temp_obj[0][2];
			for(int i=0;i<3;i++)
				temp_obj[i][2]=temp_obj[i+1][2];
			temp_obj[3][2]=t1;
		}
		for(int j=0;j<3;j++){
			Object t1 = temp_obj[0][3];
			for(int i=0;i<3;i++)
				temp_obj[i][3]=temp_obj[i+1][3];
			temp_obj[3][3]=t1;
		}
		return temp_obj;
	}

	
	public Object[][] inverse_mix_columns(Object[][]temp_obj){
		Object[][] r = new Object[4][4];
		for(int j=0;j<4;j++){
			for(int k=0;k<4;k++){
				int[][] fixed_row = new int[4][];
				int[][] binary_vals = new int[4][];
				int[][] working_result = new int[4][];
				int[] add_reslt = new int[8];
				for(int i=0;i<4;i++){
					fixed_row[i]=convert_hex_to_binary((String)shift_col_decry_vals[k][i]);//turn the byte in the constant row to polynomial
					binary_vals[i]=(convert_hex_to_binary((String)temp_obj[j][i])); //
					working_result[i]= standardization(multiplicate(binary_vals[i], fixed_row[i], false),8);
					add_reslt=standardization(Add(working_result[i], add_reslt, false),8);
				}
				String s = convert_binary_to_hex(add_reslt);
				r[j][k]=s;
			}
		}
		r = elimininate_zeros(r);
		return r;
	}

	
	public Object[][] mix_columns(Object[][]temp_obj){
		Object[][] r = new Object[4][4];
		for(int j=0;j<4;j++){
			for(int k=0;k<4;k++){
				int[][] fixed_row = new int[4][];
				int[][] binary_vals = new int[4][];
				int[][] working_result = new int[4][];
				int[] add_reslt = new int[8];
				for(int i=0;i<4;i++){
					fixed_row[i]=convert_hex_to_binary((String)shift_col_encry_vals[k][i]);
					binary_vals[i]=(convert_hex_to_binary((String)temp_obj[j][i])); //
					working_result[i]= standardization(multiplicate(binary_vals[i], fixed_row[i], false),8);
					add_reslt=standardization(Add(working_result[i], add_reslt, false),8);
				}
				String string4 = convert_binary_to_hex(add_reslt);
				r[j][k]=string4;
			}
		}
		return r;
	}	

	
	public Object[][] substitutionBytes(Object[][] temp_obj){
		for(int row=0;row<4;row++){
			for(int col=0;col<4;col++){
				int[] binary_val = convert_hex_to_binary((String) temp_obj[row][col]);
				temp_obj[row][col]= SubBytesElement(binary_val);
			}
		}
		return temp_obj;
	}
	
	public String SubBytesElement(int[]temp_obj){
		int[][] working_result = new int[8][8];
		int[] r = new int[8];
		temp_obj = EEAP_Ops(tune(temp_obj), mdeg)[0];
		temp_obj = standardization(temp_obj,8);
		temp_obj = row_to_col(temp_obj); 
		for(int i=0;i<8;i++){
			int[] temp= new int[8];

			for(int j=0;j<temp_obj.length;j++)
				temp[j]= sbox_encry_matrix[i][j] * temp_obj[j];					
			working_result[i]=temp;
		}

		for(int i=0;i<8;i++){
			for(int j=1;j<8;j++)
				working_result[i][j]=working_result[i][j]^working_result[i][j-1];					
			r[i]=working_result[i][7]^const_col_encry_vals[i]; 					
		}

		String hex_result = convert_binary_to_hex(row_to_col(r));
		return hex_result;
	}
	
	public Object[][] inverse_substitution_bytes(Object[][] temp_obj){
		for(int r=0;r<4;r++){
			for(int c=0;c<4;c++){
				temp_obj[r][c]= InvSubBytesElement(convert_hex_to_binary((String) temp_obj[r][c]));
			}
		}
		temp_obj= elimininate_zeros(temp_obj);
		return temp_obj;
	}

	
	public String InvSubBytesElement(int[]temp_obj){
		int[][] working_result = new int[8][8];
		int[] r = new int[8];
		temp_obj = row_to_col(temp_obj);
		for(int i=0;i<8;i++){
			int[] temp= new int[8];
			for(int j=0;j<temp_obj.length;j++)
				temp[j]= sbox_decry_matrix[i][j] * temp_obj[j];
			working_result[i]=temp;
		}
		for(int i=0;i<8;i++){
			for(int j=1;j<8;j++)
				working_result[i][j]=working_result[i][j]^working_result[i][j-1];
			r[i]=working_result[i][7]^const_col_decry_vals[i]; 
		}
		r= row_to_col(r);
		r = EEAP_Ops(tune(r), mdeg)[0];
		r = standardization(r,8);
		String hex_result = convert_binary_to_hex(r);
		return hex_result;
	}
	
	public int[] Add(int[] temp_obj, int[] temp_obj2, boolean plda_res){
		int[] r = new int[Math.max(temp_obj.length, temp_obj2.length)];
		if(temp_obj.length>temp_obj2.length){
			r = temp_obj.clone();
			int j = r.length-1;
			for(int i=0;i<temp_obj2.length;i++){
				r[j] ^= temp_obj2[temp_obj2.length-1-i];
				j--;
			}
		}else{
			r = temp_obj2.clone();
			int j = r.length-1;
			for(int i=0;i<temp_obj.length;i++){
				r[j] ^= temp_obj[temp_obj.length-1-i];
				j--;
			}
		}
		if(plda_res) return r;
		else return tune(PLDA_Ops(r,mdeg)[1]);
	}
	
	public int[] tune(int[] temp_obj){ 
		if(!chk_Zero(temp_obj)){
			int initial_zeros=0;
			for(int i=0;i<temp_obj.length;i++){
				if(temp_obj[i] == 0)
					initial_zeros++;
				else break;
			}
			int[] trim_res = new int[temp_obj.length-initial_zeros];
			for(int i =0;i<temp_obj.length-initial_zeros;i++){
				trim_res[i]=temp_obj[i+initial_zeros];
			}
			return trim_res;
		}
		else
		{int[] trimzero = {0};  return trimzero;}
	}
	
	public int[] modular_res(int[] temp_obj){
		for(int i=0; i<temp_obj.length;i++)
			temp_obj[i]=(temp_obj[i]%pr + pr)%pr;
		return temp_obj;
	}
	
	public boolean chk_Zero(int[] temp_obj ){
		boolean chk_zero=true;
		for(int i=0;i<temp_obj.length;i++){
			if(temp_obj[i]!=0){ 
				chk_zero=false; break;}
		}
		return chk_zero;
	}
	
	public int[] multiplicate(int[] temp_obj, int[]temp_obj2, boolean plda_res)
	{
		if(chk_Zero(temp_obj) || chk_Zero(temp_obj2))
			return new int[]{0};
		else{
			int[] r = new int[(temp_obj.length+temp_obj2.length)-1];
			for(int i=0;i<temp_obj.length;i++)
				for(int j=0;j<temp_obj2.length;j++)
					r[i+j] ^= temp_obj[i]*temp_obj2[j];
			if(plda_res)
				return r;
			else return tune(PLDA_Ops(r,mdeg)[1]);
		}
	}

	public int[][]  PLDA_Ops(int[] n, int[] d){ 
		n = modular_res(n);
		d = modular_res(d);
		int[] q = {0};
		int[] r = n;
		while(!chk_Zero(r) && ( r.length-1 >= d.length-1)){
			int tco = (((r[0]*(EEA_Ops(d[0],pr)[0])%pr)+pr)%pr);
			int t_degree = (((r.length-1) - (d.length-1))+1);
			int[] t = new int[t_degree];
			t[0]=tco;
			int[] t_times_d = multiplicate(t,d,true);
			r = Subtract(r,t_times_d,true);
			q = Add(q,t,true);
			r = modular_res(r);
			r = tune(r);
			q = modular_res(q);
			q = tune(q);
		}
		int[][] temp = new int[2][]; 
		temp[0]=q;
		temp[1]=r;
		return temp;
	}

	public int[] Subtract(int[] temp_obj, int[] temp_obj2, boolean plda_res){
		int[] r = new int[Math.max(temp_obj.length, temp_obj2.length)];
		if(temp_obj.length>temp_obj2.length){
			r = temp_obj.clone();
			int j = r.length-1;
			for(int i=0;i<temp_obj2.length;i++){
				r[j] ^= temp_obj2[temp_obj2.length-1-i];
				j--;
			}
		}else{
			r = temp_obj2.clone();
			int j = r.length-1;
			for(int i=0;i<temp_obj.length;i++){
				r[j] ^= temp_obj[temp_obj.length-1-i];
				j--;
			}
		}
		if(plda_res) return tune(r);
		else return tune(PLDA_Ops(r,mdeg)[1]);
	}
	
	public static Object[][] transform_to_state(String temp_obj){
		Object[][] working_state = new Object[4][4];
		int count=0;
		for(int i=0;i<32;i+=2){
			String temp_obj2 =  temp_obj.substring(i, i+2);
			if(i<8){
				working_state[0][count]=temp_obj2;
				if(count==3) count=-1;}
			if(i<16 &&i >7){
				working_state[1][count]=temp_obj2;
				if(count==3) count=-1;}
			if(i<24 && i>15){
				working_state[2][count]=temp_obj2;
				if(count==3) count=-1;}
			if(i<32 && i>23)
				working_state[3][count]=temp_obj2;
			count++;
		}
		return working_state;
	}
	
	public static String transform_state_to_string(Object[][] temp_obj){
		String string5="";
		for(int i=0;i<4;i++){
			for(int j=0;j<4;j++)
				string5+=(String)temp_obj[i][j];
		}
		return string5;
	}

	public static void DumpState(String name, Object[][] state) {
		System.out.println(name + ":");
		for(int i=0;i<4;i++) {
			for(int j=0;j<4;j++){
				System.out.print(state[j][i] + " ");
			}
			System.out.println();
		}
	}
	
	public static Object[][] elimininate_zeros(Object[][]temp_obj){
		for(int i=0;i<4;i++){
			for(int j=0;j<4;j++){
				String string6= (String)temp_obj[i][j];
				if(string6.length()==1){
					string6="0"+string6;
					temp_obj[i][j]=string6;
				}
			}
		}
		return temp_obj;
	}

	public static String convert_binary_to_hex(int[] temp_obj){
		String binary_val="";
		for(int i=0;i<temp_obj.length;i++)
			binary_val += ""+temp_obj[i];
		String string7 = Long.toHexString(Long.parseLong(binary_val, 2));
		return string7;
	}

	public static int[] row_to_col(int[] temp_obj){

		int[] rev = temp_obj.clone();
		int j=0;
		for(int i=rev.length-1;i>=0;i--)
		{rev[i]=temp_obj[j]; j++;}
		return rev;
	}

	public static int[] convert_hex_to_binary(String temp_obj){
		int[] r = new int[8];
		String string8 = new BigInteger(temp_obj, 16).toString(2);
		char[] arr = string8.toCharArray();
		int j=r.length-1;
		for(int i=arr.length-1;i>=0;i--){
			r[j]=Integer.parseInt(""+arr[i]);
			j--;
		}
		return r;
	}
	
		public Object[][][] on_key_workings(Object[][]temp_obj){
		Object[][] prevKey = temp_obj;
		Object[][][] r= new Object[10][][];
		for(int round=0;round<10;round++){
			Object[][] current_Key = new Object[4][];
			Object[] temp_1_obj = prevKey[3];
			Object[] temp = temp_1_obj.clone();
			Object t = temp[0];
			for(int i=0;i<3;i++)
				temp[i]=temp[i+1];
			temp[3]=t;
			for(int i=0;i<4;i++)
				temp[i]=SubBytesElement(convert_hex_to_binary((String)temp[i])); //rotate
				int[] t0=convert_hex_to_binary((String)temp[0]);
				int[] rndcst=convert_hex_to_binary(rouund_constants[round]);
				for(int i=0;i<8;i++)
					t0[i]=t0[i]^rndcst[i];
				temp[0]= convert_binary_to_hex(t0);		
				int[] res;
				int[] curtemp= convert_hex_to_binary((String)temp[0]);
				Object intermediate = prevKey[0][0];
				int[] pretemp= convert_hex_to_binary((String)intermediate);
				res = Add(curtemp, pretemp, false);
				String strConvert = convert_binary_to_hex(res);
				for(int i=0;i<4;i++){
					int[] currtemp= convert_hex_to_binary((String)temp[i]);
					int[] prevtemp= convert_hex_to_binary((String)prevKey[0][i]);
					for(int temp_obj2=0;temp_obj2<8;temp_obj2++)
						currtemp[temp_obj2]= currtemp[temp_obj2]^prevtemp[temp_obj2];
					temp[i]= convert_binary_to_hex(currtemp);
				}
				current_Key[0]=temp;
				Object[] resultcol1= new Object[4];
				for(int i=0;i<4;i++)
					resultcol1[i]=convert_binary_to_hex(Add(convert_hex_to_binary((String)prevKey[1][i]),convert_hex_to_binary((String)current_Key[0][i]), false)); //xoring an entire column
				current_Key[1]=resultcol1;
				Object[] resultcol2= new Object[4];
				for(int i=0;i<4;i++)
					resultcol2[i]=convert_binary_to_hex(Add(convert_hex_to_binary((String)prevKey[2][i]),convert_hex_to_binary((String)current_Key[1][i]), false)); //xoring an entire column
				current_Key[2]=resultcol2;
				Object[] resultcol3= new Object[4];
				for(int i=0;i<4;i++)
					resultcol3[i]=convert_binary_to_hex(Add(convert_hex_to_binary((String)prevKey[3][i]),convert_hex_to_binary((String)current_Key[2][i]), false)); //xoring an entire column
				current_Key[3]=resultcol3;

				r[round]=current_Key;
				prevKey=current_Key;
		}
		return r;
	}
	
	public int[] standardization(int[] temp_obj,int temp_obj2){
		int[] temp=new int[temp_obj2];
		int j=temp.length-1;
		for(int i=temp_obj.length-1;i>=0;i--)
		{temp[j]=temp_obj[i];j--;}
		return temp;
	}
	
	public int[] EEA_Ops(int temp_obj, int temp_obj2){ 
		if(temp_obj2 == 0){
			return new int[]{1,0};
		}else{
			int quotint = temp_obj/temp_obj2; int r = temp_obj%temp_obj2;
			int[] reminder = EEA_Ops(temp_obj2,r);
			return new int[]{reminder[1], reminder[0]-quotint*reminder[1]};
		}
	}
	
	public int[][] EEAP_Ops(int[] temp_obj, int[] temp_obj2){ 
		int[][] rslt = new int[2][];
		temp_obj = modular_res(temp_obj);
		temp_obj2 = modular_res(temp_obj2);
		if(chk_Zero(temp_obj2)){
			temp_obj=tune(temp_obj);
			int[] q = {((((EEA_Ops(temp_obj[0],pr)[0])%pr)+pr)%pr)};
			int[] z = {0};
			rslt[0]=q;
			rslt[1]=z;
			return rslt;
		}else{
			int[][]Q = PLDA_Ops(temp_obj,temp_obj2);
			int[] q = Q[0];
			int[] r = Q[1];
			int[][] R = EEAP_Ops(temp_obj2,r);
			int[] firstp = modular_res(R[1]);
					int[] mul_result = multiplicate(q,R[1],false);
					int[] sub_result = Subtract(R[0],mul_result,false);
					int[] secondp = modular_res(sub_result);
					R[0]=firstp;
					R[1]=secondp;
					return(R);
		}
	}
}