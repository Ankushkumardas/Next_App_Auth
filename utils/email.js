import nodemailer from 'nodemailer';

const sendemail = async (options) => {
    if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
        throw new Error('EMAIL_USER and EMAIL_PASS environment variables must be set');
    }
    if (!options || !options.email || !options.subject || !options.otp) {
        throw new Error('Options object with email, subject, and otp fields is required');
    }

    const transporter = nodemailer.createTransport({
        service: "Gmail",
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS,
        }
    });

    const mailoptions = {
        from: `"Admin" <${process.env.EMAIL_USER}>`,
        to: options.email,
        subject: options.subject,
        html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; border: 1px solid #eee; border-radius: 8px; padding: 24px; background: #fafbfc;">
                <h2 style="color: #2d3748; margin-bottom: 16px;">${options.subject}</h2>
                <div style="color: #4a5568; font-size: 16px; line-height: 1.6;">
                    ${options.otp}
                </div>
                <hr style="margin: 32px 0; border: none; border-top: 1px solid #e2e8f0;">
                <div style="font-size: 13px; color: #a0aec0;">
                    If you did not request this email, you can safely ignore it.
                </div>
            </div>
        `
    };

    try {
        await transporter.sendMail(mailoptions);
    } catch (error) {
        console.error('Error sending email:', error);
        throw error;
    }
}

export default sendemail;