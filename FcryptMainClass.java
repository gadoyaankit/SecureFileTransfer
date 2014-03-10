public class FcryptMainClass {
	public static void main(String args[]){
		/*
		 * Get the mode of the program
		 */
		byte mode=-1;
		if(args[0].endsWith("-e")){
			mode=0;
		}
		else{
			if(args[0].equals("-d")){
				mode=1;
			}
			else{
				mode=-1;
			}
		}
		/*
		 * run the program in the mode given
		 */
		switch(mode){
			case 0:
				new FileEncrypt().encryptMode(args);
				break;
			case 1:
				new FileDecrypt().decryptMode(args);
				break;
			case -1:
				System.err.println("Pass -e for encryption, " +
						"-d for decryption. Other parameters are ignored.");
				
		}
	}
	

}

