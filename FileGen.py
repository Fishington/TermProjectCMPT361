import random
import string

def create_long_text_file(filename, length):
  """
  Creates a text file with a specified number of random characters.

  Args:
    filename: The name of the file to create.
    length: The desired number of characters in the file.
  """
  # Define the characters to be used in the random string
  characters = string.ascii_letters + string.digits + string.punctuation
  
  # Generate the random string
  random_string = ''.join(random.choice(characters) for i in range(length))
  
  # Write the string to the specified file
  with open(filename, 'w') as f:
    f.write(random_string)

# Define the desired filename and character length
file_to_create = "250000.txt"
character_length = 250000

# Create the file
create_long_text_file(file_to_create, character_length)