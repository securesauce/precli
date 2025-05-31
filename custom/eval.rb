# Simulated user input
user_code = gets.chomp

# Dangerous: evaluates user-supplied input as Ruby code
eval(user_code)
