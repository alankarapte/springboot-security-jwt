# Getting Started

# By ALANKAR-

# Objective
Create new authentication API endpoint
Examine every request incoming request for valid JWT & authorize it

# Step 0 
A starter spring security application
with 
One hardcoded user 
e.g. 
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		return new User("admin", "admin", new ArrayList<>()); //TODO: hardcoded username & password
	} 

# Step 1
A /authenticate API endpoint 
-which accept user ID & password
-Returns a JWT as response

# Step 2
Intercept all incoming requests
-Extract JWT from the header 
-Validate & set in execution context

