const { expect } = require("chai");

describe("Add", function () {
  it("should return the sum of two numbers", async function () {
    const Add = await ethers.getContractFactory("Add");
    const add = await Add.deploy();

    const result = await add.add(2, 3);
    expect(result).to.equal(5);
  });
});

describe("Helloworld",function() {
    it("should return the hello world",async function() {
        const Helloworld = await ethers.getContractFactory("Helloworld");
        const helloworld = await Helloworld.deploy();

        const result = await helloworld.hello();
        expect(result).to.equal("Hello World");
    })
})