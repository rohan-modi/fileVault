# Use official Node.js image
FROM node:16

# Set the working directory in the container to /backend
WORKDIR /backend

# Copy the package.json and package-lock.json files into the container's /backend directory
COPY backend/package*.json ./

# Install dependencies
RUN npm install

# Copy the rest of the backend code into the container
COPY backend/ .
COPY ../frontend ./frontend
COPY . .

# Expose the port
EXPOSE 5001

# Command to run the app
CMD ["npm", "start"]
