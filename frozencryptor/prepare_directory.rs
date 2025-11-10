// Author: Jason Kelly
// Purpose: Encryption preparation utility
// Date: 07/08/25

// Imports
// Standard Library
use std::path::{PathBuf,Path};
use std::fs::{File,create_dir_all};
use std::io::Write;
use std::env;
use std::sync::{Arc,atomic::{AtomicUsize,Ordering::SeqCst}};

// Randomised File Names
use random_word::Lang;

// Multithreading
use rayon::prelude::*;

//Runtime Configuration Struct
#[derive(Debug)]
struct RuntimeConfiguration {
	target_folder:String
}

// Print Help Function
fn print_help() {
	println!(r#"Usage: prepare_directory.exe -t {{target_folder}}
	-t : Folder to use"#);
}

// Argument Parser
fn parse_arguments(runtime_config:&mut RuntimeConfiguration,commandline_args:&Vec<String>) -> bool {
	if commandline_args.len() == 0 {
		println!("Please provide arguments and try again!\n");
		print_help();
		return false;
	}
	for (position,argument) in commandline_args.iter().enumerate() {
		let case_neutral_argument:String = argument.to_lowercase();
		// Run Operation
		if case_neutral_argument == "-t" {
			if commandline_args.len()-1 >= position+1 {
				runtime_config.target_folder=String::from(commandline_args[position+1].as_str());
			}
			else {
				println!("Please supply a value for the target directory!");
				print_help();
				return false;
			}
		}
	}
	return true;
}

// Argument Validator
fn validate_arguments(runtime_config:&RuntimeConfiguration) -> bool {
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
	let files_created:Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
	let folders_created:Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));

	match create_folders(base_folder, width, deep, file_limit, Arc::clone(&files_created), Arc::clone(&folders_created)) {
		Ok(_) => { },
		Err(e) => {println!("Failed to prepare directory structure: {e}"); return false}
	}
	println!("Folders created: {}\nFiles Created: {}\n",folders_created.load(SeqCst),files_created.load(SeqCst));
	
	return true;
}
fn create_folders(base_path:PathBuf, width:i8, depth:i8, file_limit:i8, file_count:Arc<AtomicUsize>, folder_count:Arc<AtomicUsize>) -> Result<(),String> {
	// Clone file count for multithreading
	let file_count_clone:Arc<AtomicUsize> = Arc::clone(&file_count);
	// Create files here regardless
	if !create_files(&base_path, file_limit, file_count_clone) {
		println!("Failed to create files in the folder during prep!");
		return Err("Failed to create files".to_string());
	}
	// Since decrement is done, we're done depth wise
	if depth==0 {
		return Ok(());
	}
	// Let Rayon initialise parallel threads for us
	match (0..width).into_par_iter().try_for_each(|_| {
		//FORDEBUG: println!("Depth: {}\n Width: {}", depth, width);
		//create_files(&base_path.clone(), file_limit, file_count);
		let mut current_folder_path:PathBuf = base_path.clone();
		let foldername:String = String::from(random_word::get(Lang::En));

		// Add the new folder on to the current path
		current_folder_path.push(format!("{}", foldername));
		match create_dir_all(&current_folder_path).map_err(|e| format!("Failed to create folder {}", e)) {
			Ok(_empty) => {folder_count.fetch_add(1, SeqCst);}
			Err(e) => {println!("Failed to create folder during prep: {}", e); return Err("Failed to create directory!".to_string());}
		}
		// Recursive call to move to next depth
		match create_folders(current_folder_path, width, depth-1, file_limit, Arc::clone(&file_count), Arc::clone(&folder_count)) {
			Ok(_empty) => {return Ok(())},
			Err(e) => {return Err(e);}
		}
	}) {
		Ok(_empty) => {}
		Err(e) => {println!("Failed to create folder during prep: {}", e)}
	}
	return Ok(());
}

// Create files
fn create_files(folder:&PathBuf,file_limit:i8, file_count:Arc<AtomicUsize>) -> bool {
	let text_file_contents:String = String::from("These are some very important business documents! Hope no one alters them in any way!");
	let csv_file_contents:String = String::from("SSN,gender,birthdate,maiden name,last name,first name,address,city,state,zip,phone,email,cc_type,CCN,cc_cvc,cc_expiredate\n172-32-1176,m,4/21/1958,Smith,White,Johnson,10932 Bigge Rd,Menlo Park,CA,94025,408 496-7223,jwhite@domain.com,m,5270-4267-6450-5516,123,25/06/2010\n514-14-8905,f,12/22/1944,Amaker,Borden,Ashley,4469 Sherman Street,Goff,KS,66428,785-939-6046,aborden@domain.com,m,5370-4638-8881-3020,713,01/02/2011\n213-46-8915,f,4/21/1958,Pinson,Green,Marjorie,309 63rd St. #411,Oakland,CA,94618,415 986-7020,mgreen@domain.com,v,4916-9766-5240-6147,258,25/02/2009\n524-02-7657,m,3/25/1962,Hall,Munsch,Jerome,2183 Roy Alley,Centennial,CO,80112,303-901-6123,jmunsch@domain.com,m,5180-3807-3679-8221,612,01/03/2010\n489-36-8350,m,06/09/1964,Porter,Aragon,Robert,3181 White Oak Drive,Kansas City,MO,66215,816-645-6936,raragon@domain.com,v,4929-3813-3266-4295,911,01/12/2011\n514-30-2668,f,27/05/1986,Nicholson,Russell,Jacki,3097 Better Street,Kansas City,MO,66215,913-227-6106,jrussell@domain.com,a,3.4539E+14,232,01/01/2010\n505-88-5714,f,23/09/1963,Mcclain,Venson,Lillian,539 Kyle Street,Wood River,NE,68883,308-583-8759,lvenson@domain.com,d,3.02049E+13,471,01/12/2011\n690-05-5315,m,02/10/1969,Kings,Conley,Thomas,570 Nancy Street,Morrisville,NC,27560,919-656-6779,tconley@domain.com,v,4916 4811 5814 8111,731,01/10/2010\n646-44-9061,M,12/01/1978,Kurtz,Jackson,Charles,1074 Small Street,New York,NY,10011,212-847-4915,cjackson@domain.com,m,5218 0144 2703 9266,892,01/11/2011\n421-37-1396,f,09/04/1980,Linden,Davis,Susan,4222 Bedford Street,Jasper,AL,35501,205-221-9156,sdavis@domain.com,v,4916 4034 9269 8783,33,01/04/2011\n461-97-5660,f,04/01/1975,Kingdon,Watson,Gail,3414 Gore Street,Houston,TX,77002,713-547-3414,gwatson@domain.com,v,4532 1753 6071 1112,694,01/09/2011\n660-03-8360,f,11/07/1953,Onwunli,Garrison,Lisa,515 Hillside Drive,Lake Charles,LA,70629,337-965-2982,lgarrison@domain.com,v,4539 5385 7425 5825,680,01/06/2011\n751-01-2327,f,16/02/1968,Simpson,Renfro,Julie,4032 Arron Smith Drive,Kaunakakai,HI,96748,808-560-1638,jrenfro@domain.com,m,5325 3256 9519 6624,238,01/03/2009\n559-81-1301,m,20/01/1952,Mcafee,Heard,James,2865 Driftwood Road,San Jose,CA,95129,408-370-0031,jheard@domain.com,v,4532 4220 6922 9909,311,01/09/2010\n624-84-9181,m,16/01/1980,Frazier,Reyes,Danny,3500 Diane Street,San Luis Obispo,CA,93401,805-369-0464,dreyes@domain.com,v,4532 0065 1968 5602,713,01/11/2009\n449-48-3135,m,14/06/1982,Feusier,Hall,Mark,4986 Chapel Street,Houston,TX,77077,281-597-5517,mhall@domain.com,v,4556 0072 1294 7415,953,01/05/2010\n477-36-0282,m,10/03/1961,Vasquez,Mceachern,Monte,456 Oral Lake Road,Minneapolis,MN,55401,952-412-3707,mmceachern@domain.com,m,5527 1247 5046 7780,889,01/03/2009\n458-02-6124,m,20/09/1955,Pennebaker,Diaz,Christopher,582 Thrash Trail,Dallas,TX,75247,903-624-9156,cdiaz@domain.com,m,5299 1561 5689 1938,584,01/08/2011\n044-34-6954,m,28/05/1967,Simpson,Lowe,Tim,1620 Maxwell Street,East Hartford,CT,6108,860-755-0293,tlowe@domain.com,m,5144 8691 2776 1108,616,01/10/2011\n587-03-2682,f,24/10/1958,Dickerson,Oyola,Lynette,2489 O Conner Street,Pascagoula,MS,39567,228-938-2056,loyola@domain.com,v,4532 9929 3036 9308,991,01/07/2011\n421-90-3440,f,17/07/1953,Kroeger,Morrison,Adriane,4696 Retreat Avenue,Birmingham,AL,35209,205-276-1807,amorrison@domain.com,v,4539 0031 3703 0728,322,01/12/2009\n451-80-3526,m,09/06/1950,Parmer,Santos,Thomas,173 Lunetta Street,Fort Worth,TX,76104,940-859-1393,tsantos@domain.com,v,4716 6984 4983 6160,767,01/09/2011\n300-62-3266,m,10/02/1965,Spain,Faulkner,Victor,1843 Olive Street,Toledo,OH,43602,419-340-3832,vfaulkner@domain.com,m,5548 0246 6336 5664,276,01/02/2010\n322-84-2281,m,19/08/1977,Miley,Iorio,Albert,4899 University Hill Road,Springfield,IL,62701,217-615-6419,aiorio@domain.com,v,4916 6734 7572 5015,347,01/02/2010\n465-73-5022,f,20/06/1964,Summers,Kaminski,Teresa,1517 Gambler Lane,Houston,TX,77006,281-906-2148,tkaminski@domain.com,m,5399 0706 4128 0178,721,01/10/2009\n612-20-6832,m,18/08/1979,Banas,Edwards,Rick,4254 Walkers Ridge Way,Gardena,CA,90248,626-991-3620,redwards@domain.com,m,5293 8502 0071 3058,701,01/08/2010\n687-05-8365,f,24/05/1976,Robbins,Peacock,Stacey,3396 Nancy Street,Raleigh,NC,27612,919-571-2339,speacock@domain.com,m,5495 8602 4508 6804,436,01/02/2011\n205-52-0027,f,26/03/1950,Sanford,Nelson,Agnes,4213 High Meadow Lane,Avoca,PA,18641,570-480-8704,anelson@domain.com,m,5413 4428 0145 0036,496,01/02/2010\n404-12-2154,f,21/09/1984,Garcia,Townsend,Mireille,2877 Glen Street,Paducah,KY,42003,270-408-7254,mtownsend@domain.com,v,4539 8219 0484 7598,710,01/03/2011\n151-32-2558,f,19/11/1952,Stockdale,Zwick,Rebecca,784 Beechwood Avenue,Piscataway,NJ,8854,908-814-6733,rzwick@domain.com,v,5252 5971 4219 4116,173,01/02/2011");
	let mut current_folder:PathBuf = folder.clone();
	let mut file_contents:String;
	for file_number in 0..file_limit {
		let filename:String = String::from(random_word::get(Lang::En));
		if file_number < (file_limit/2) {
			current_folder.push(format!("{}.txt",filename));
			file_contents=text_file_contents.clone();
		}
		else {
			current_folder.push(format!("{}.csv",filename));
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
		file_count.fetch_add(1, SeqCst);
		current_folder.pop();
	}
	return true;
}

fn main() {
	let mut runtime_config:RuntimeConfiguration = RuntimeConfiguration {
		target_folder: String::from("C:\\Windows\\Temp"),
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
	prep(&runtime_config.target_folder);
}