const generateOtp = () => {
    return Math.floor(10000 * Math.random().toString());
};

export default generateOtp;