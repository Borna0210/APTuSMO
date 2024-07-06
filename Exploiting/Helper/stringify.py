def list_to_comma_separated_string(input_list):
    # Convert list to a comma-separated string
    comma_separated_string = ','.join(map(str, input_list))
    # Add double quotes at the beginning and end
    return comma_separated_string