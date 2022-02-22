%%{

    machine _0_65535;

    _0_65535 = (

        # this parser parses a number between 0 and 65535 inclusive

        # If it's a 0, we're done immediately, nothing else to do.
        '0'
        
        # low numbers - 1-5, 10000-19999, 50000-59999,
        | [1-5] [0-9]{0,4}

        # high numbers - 7-9, 70-79, 90-99, 700-799, 900-999, 7000, 9999
        | [7-9] [0-9]{0,3}

        # breaking point
        | '6' (
            
            # low numbers: 60 - 64, 60xxx - 64xxx
            [0-4] [0-9]{0,3}

            # high numbers: 66, 69, 66xxx, 69xxx
            | [6-9] [0-9]{0,2}

            # breaking point: 65, 65xxxx
            | '5' (

                # low numbers: 650, 654, 6500, 65499
                [0-4] [0-9]{0,2}

                # high numbers: 656, 659, 6560, 6599
                | [6-9] [0-9]{0,2}

                # breaking point: 655, 655x, 655xx
                | '5' (

                    # low numbers: 6550, 6552, 65500, 65529
                    [0-2] [0-9]?

                    # high numbers: 6554, 6559
                    [4-9]

                    # breaking point: 6553, 6553x
                    | '3'

                        # low numbers: 65530, 65535
                        [0-5]?

                )?
            )?
        )?
    );

}%%
