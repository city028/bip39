// links for reference
// https://doc.rust-lang.org/book/ch12-01-accepting-command-line-arguments.html
// https://docs.rs/sha2/latest/sha2/
// https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
use std::env;
// For use by the file option
use std::fs::File;
use std::io::Read;

// Remember to add the following to the Carog.toml dependencies section: sha2 = "0.10.2"
use sha2::{Sha256, Digest};

// Added to keep the long list of seed words in a seperate file ./langauge/mod.rs
mod language;
use crate::language::GBWORDS;

// Descripton: this programme creates a 24 word seed phrase from either a phrase provides as input or a file
//
// Input: phrase or file
//
// >bip39 --ip '<phrase>'
// >bip39 --if '<filename>'
//
// Output: 24 word seed phrase
fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();

    // create Sha256 objects
    let mut prehasher = Sha256::new();
    let mut hasher = Sha256::new();

    // Array to store the sha-256 hash (32 bytes) plus 1 byte checksum = 33 bytes
    let mut hashcheck = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
    // Array to store the Seed phrase values = 24 x u32 values of which 11 bits are used
    let mut seedvalues = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];

    // Check if any arguments are provided
    if args.len() >= 2
    {
        // Check the first argument
        let command = &args[1];
        match command.as_str()
        {
            "--ip" =>   {   // This is the pass phrase input command
                            // Check if a second arg has been provided
                            if args.len() == 3
                            {
                                // Get the phrase
                                let phrase = &args[2];
                                // println!("The following phrase has been provided: {}", phrase );

                                //pre-hasher to create a 256 bit input from the phrase provided as input to the hasher
                                prehasher.update(phrase);                       // hash phrase
                                let prehash = prehasher.finalize();

                                // shas-256 the phrase to get a 256 bit entropy
                                hasher.update(prehash);                         // 256 bit input being hased
                                let entropy = hasher.finalize();
                                //println!("{:?}", entropy);                      // Debug, print out the entropy 256 bits

                                // debug, print LSB as this is the checksum to be added as the msb
                                //println!("{:?}", entropy[31] );     //LSB is last in array of hasher result, this needs to be appended to the end

                                hashcheck[32] = entropy[31];                        // set checksum of LSB in last byte of hascheck

                                // Fill hashcheck with entropy with LSB in spot 0 and MSB in 31
                                let mut hascnt = 0;
                                let mut entrcnt = 31;
                                hashcheck[31] = entropy[0];         // Copy MSB in hascheck
                                while entrcnt != 0                  // copy rest of bytes
                                {
                                    hashcheck[hascnt] = entropy[entrcnt];
                                    hascnt = hascnt + 1;
                                    entrcnt = entrcnt - 1;
                                }
                                // we now have LSB in spot 0, MSB in spot 31 and checksum in spot 32 (which is LSB)
                                //println!("{:?}", hashcheck );       // Debug
                                // done with the entrophy, now go and look up the seed words
                            }
                            else
                            {
                                println!("Error, the --ip command needs to be followed by a phrase between '', use --help for more information!");
                            }
                        },
            "--if" =>   {
                            // Check if a second arg has been provided
                            if args.len() == 3
                            {
                                let filename = &args[2];

                                //Generate entrophy by using a file
                                //println!("The following file name has been provided: {}",filename );

                                if filename != ""
                                {
                                    //Open the file and create a source for the hasher to create a 256 bit input as an entropy
                                    let mut f = File::open(filename).expect("no file found");
                                    let metadata = File::metadata(&f).expect("unable to read metadata");
                                    let mut buffer = vec![0; metadata.len() as usize];
                                    f.read(&mut buffer).expect("buffer overflow");

                                    //pre-hasher to create a 256 bit input from the phrase provided as input to the hasher
                                    prehasher.update(buffer);                       // hash phrase
                                    let prehash = prehasher.finalize();

                                    // shas-256 the phrase to get a 256 bit entropy
                                    hasher.update(prehash);                         // 256 bit input being hased
                                    let entropy = hasher.finalize();
                                    //println!("{:?}", entropy);                      // Debug, print out the entropy 256 bits

                                    // debug, print LSB as this is the checksum to be added as the msb
                                    //println!("{:?}", entropy[31] );     //LSB is last in array of hasher result, this needs to be appended to the end

                                    hashcheck[32] = entropy[31];                        // set checksum of LSB in last byte of hascheck

                                    // Fill hashcheck with entropy with LSB in spot 0 and MSB in 31
                                    let mut hascnt = 0;
                                    let mut entrcnt = 31;
                                    hashcheck[31] = entropy[0];         // Copy MSB in hascheck
                                    while entrcnt != 0                  // copy rest of bytes
                                    {
                                        hashcheck[hascnt] = entropy[entrcnt];
                                        hascnt = hascnt + 1;
                                        entrcnt = entrcnt - 1;
                                    }
                                    // we now have LSB in spot 0, MSB in spot 31 and checksum in spot 32 (which is LSB)
                                    //println!("{:?}", hashcheck );       // Debug
                                    // done with the entrophy, now go and look up the seed words
                                }
                                else
                                {
                                    println!("Error, the --if command needs to be followed by a filename, between '', it cannot be blank, use --help for more information!");
                                }

                            }
                            else
                            {
                                println!("Error, the --if command needs to be followed by a filename between'', use --help for more information!");
                            }
                        },
            "--help" => {
                            println!("Commands supported:");
                            println!(r#"--ip '<phrase>'"#);         // use r# to print the raw string
                            println!(r#"--if '<file name>'"#);
                            println!("--help");
                        },
            _ => println!("Error, command not supported, use --help to get information on commands supported"),
        }


        // Now that the entropy is created proceed with the rest of the process
        let mut bytecnt = 0;                //0 - 32 as there are 33 bytes in hashcheck
        let mut bytecntfl = 0 as f32;
        let mut bitcnt = 0;
        let mut bitshift = 0;               // for the first calculation no shift is required hence 0
        let mask:u32 = 2047;                // 2047 = b00000000000000000000011111111111; = 11 bits mask
        let mut seedval:u32 = 0;
        let mut seedcnt = 0;

        //start loop to split the hash + checksum into 11 bit chunks and store the seed values
        while seedcnt < 24                                                                              // seed count = 0 - 23, exit when 24
        {
            // create u32 from bytes in hashcheck
            if bytecnt + 3 < 33 {seedval = hashcheck[bytecnt+3] as u32;} else { seedval = 0}            // make sure that the bytcnt index does not extend beyond the length of the array
            //println!("{:?}", seedval );
            seedval = seedval << 8;
            //println!("{:?}", seedval );
            if bytecnt + 2 < 33 {seedval = seedval + hashcheck[bytecnt+2] as u32;} else { seedval = 0}  // make sure that the bytcnt index does not extend beyond the length of the array
            //println!("{:?}", seedval );
            seedval = seedval << 8;
            //println!("{:?}", seedval );
            if bytecnt + 1 < 33 {seedval = seedval + hashcheck[bytecnt+1] as u32; } else {seedval = 0}  // make sure that the bytcnt index does not extend beyond the length of the array
            //println!("{:?}", seedval );
            seedval = seedval << 8;
            //println!("{:?}", seedval );
            seedval = seedval + hashcheck[bytecnt] as u32;
            //println!("{:?}", seedval );

            // Shift bits to the right if required
            seedval =  seedval >> bitshift;

            //Now mask out 11 bits
            seedval = seedval & mask;
            //println!("{:?}", seedval );

            // store seed values
            seedvalues[seedcnt] = seedval;
            seedval = 0;                            //reset seedval to 0 just to make sure
            seedcnt = seedcnt + 1;
            //println!("seedvalues: {:?}", seedvalues );
            //println!("seedcnt: {:?}", seedcnt );

            // increase values to go into the next loop
            bitcnt = bitcnt + 11;                                   // next 11 bytes
            bytecntfl = bitcnt as f32 / 8 as f32;                   // calculate the next byte offset
            bytecnt = bytecntfl.trunc() as usize;                   // use only the integer part of the number

            //println!("bytecntfl: {:?}", bytecntfl );
            //println!("bytecntfl (trunc): {:?}", bytecntfl.trunc() );
            //println!("bytecnt {:?}", bytecnt );

            bitshift = bitcnt - ( bytecnt * 8);                     // calculate the bit shift to the right required
            //println!("bitshift: {:?}", bitshift );
            // end of calcs
        }
        //end loop, the seedvalues array now stores all the seed phrase seedvalues

        //look up the values in the table and display the seed words generated
        seedcnt = 0;
        println!("Your seed phrase is shown below:");
        println!();
        while seedcnt < 24
        {
            print!("{} ", GBWORDS[ seedvalues[seedcnt] as usize - 1] );
            seedcnt = seedcnt + 1;
        }
        println!();
        println!();
        println!("Please copy it and keep it safe!");
    }
    else
    {
        println!("Error, this programme needs at least 1 paramater, use --help for more information!");
    }

    Ok(())
}
