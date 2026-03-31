# Steps to clone template

1. Create folder for your project and cd into it

2. Perform the following commands in the command line
```bash
git clone https://github.com/SEB-PT-8/Unit03-Auth-Template-Backend.git .
rm -rf .git
rm README.md
```

3. Create a .env file with the following 2 values of your database connection:
```
MONGODB_URI=mongodb+srv://<username>:<password>@cluster0.jbfjdbbdkkj.mongodb.net/libraryDB?retryWrites=true&w=majority&appName=Cluster0
JWT_SECRET=L2d6ZjAV
```


4. run:
```bash
npm i
```




