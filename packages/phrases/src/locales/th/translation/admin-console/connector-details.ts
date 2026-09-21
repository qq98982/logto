const connector_details = {
  page_title: 'รายละเอียดตัวเชื่อมต่อ',
  back_to_connectors: 'กลับไปยังตัวเชื่อมต่อ',
  check_readme: 'ดู README',
  settings: 'การตั้งค่าทั่วไป',
  settings_description:
    'รวมผู้ให้บริการภายนอกเพื่อเข้าสู่ระบบด้วยโซเชียลอย่างรวดเร็วและเชื่อมโยงบัญชีโซเชียล',
  setting_description_with_token_storage_supported:
    'รวมผู้ให้บริการภายนอกเพื่อเข้าสู่ระบบด้วยโซเชียลอย่างรวดเร็ว เชื่อมโยงบัญชีโซเชียล และเข้าถึง API ได้',
  email_connector_settings_description:
    'เชื่อมต่อกับผู้ให้บริการอีเมลของคุณเพื่อเปิดใช้งานการลงทะเบียนและเข้าสู่ระบบแบบไม่ใช้รหัสผ่านสำหรับผู้ใช้',
  parameter_configuration: 'การกำหนดค่าพารามิเตอร์',
  test_connection: 'ทดสอบ',
  save_error_empty_config: 'กรุณากรอกการตั้งค่า',
  send: 'ส่ง',
  send_error_invalid_format: 'รูปแบบข้อมูลไม่ถูกต้อง',
  edit_config_label: 'กรอก JSON ของคุณที่นี่',
  test_email_sender: 'ทดสอบตัวเชื่อมต่ออีเมลของคุณ',
  test_sms_sender: 'ทดสอบตัวเชื่อมต่อ SMS ของคุณ',
  test_email_placeholder: 'john.doe@example.com',
  test_sms_placeholder: '+1 555-123-4567',
  test_message_sent: 'ส่งข้อความทดสอบแล้ว',
  test_sender_description:
    'Aster ใช้แม่แบบ "Generic" สำหรับการทดสอบ คุณจะได้รับข้อความหากตัวเชื่อมต่อของคุณตั้งค่าอย่างถูกต้อง',
  options_change_email: 'เปลี่ยนตัวเชื่อมต่ออีเมล',
  options_change_sms: 'เปลี่ยนตัวเชื่อมต่อ SMS',
  connector_deleted: 'ลบตัวเชื่อมต่อเรียบร้อยแล้ว',
  type_email: 'ตัวเชื่อมต่ออีเมล',
  type_sms: 'ตัวเชื่อมต่อ SMS',
  type_social: 'ตัวเชื่อมต่อโซเชียล',
  in_used_social_deletion_description:
    'ตัวเชื่อมต่อนี้ถูกใช้งานในประสบการณ์การลงชื่อเข้าใช้ของคุณ เมื่อคุณลบ <name/> ประสบการณ์การลงชื่อเข้าใช้รายนี้จะถูกลบจากการตั้งค่าประสบการณ์การลงชื่อเข้าใช้ คุณต้องตั้งค่าใหม่หากต้องการเพิ่มกลับเข้ามาอีกครั้ง',
  in_used_passwordless_deletion_description:
    'ตัวเชื่อมต่อ {{name}} นี้ถูกใช้งานในประสบการณ์การลงชื่อเข้าใช้ของคุณ เมื่อคุณลบ การลงชื่อเข้าใช้ของคุณจะทำงานไม่ถูกต้องจนกว่าคุณจะแก้ไขปัญหา คุณต้องตั้งค่าใหม่หากต้องการเพิ่มกลับเข้ามาอีกครั้ง',
  deletion_description:
    'คุณกำลังลบตัวเชื่อมต่อนี้ การดำเนินการนี้ไม่สามารถย้อนคืนได้ และคุณต้องตั้งค่าใหม่หากต้องการเพิ่มกลับเข้ามาอีกครั้ง',
  google_one_tap: {
    title: 'Google One Tap',
    description: 'Google One Tap เป็นวิธีที่ปลอดภัยและง่ายสำหรับผู้ใช้ในการเข้าสู่เว็บไซต์ของคุณ',
    enable_google_one_tap: 'เปิดใช้งาน Google One Tap',
    enable_google_one_tap_description:
      'เปิดใช้งาน Google One Tap ในประสบการณ์ลงชื่อเข้าใช้: ให้ผู้ใช้สมัครหรือลงชื่อเข้าใช้ด้วยบัญชี Google ได้อย่างรวดเร็วหากพวกเขาได้ลงชื่อเข้าใช้ไว้แล้วในอุปกรณ์',
    configure_google_one_tap: 'ตั้งค่า Google One Tap',
    auto_select: 'เลือกรับรองความถูกต้องโดยอัตโนมัติถ้าเป็นไปได้',
    close_on_tap_outside: 'ยกเลิกข้อความแจ้งถ้าผู้ใช้งานแตะภายนอก',
    itp_support: 'เปิดใช้ <a>One Tap UX แบบอัปเกรดบนเบราว์เซอร์ ITP</a>',
  },
  sign_in_experience: {
    in_use: 'เปิดใช้งานสำหรับการเข้าสู่ระบบ ',
    not_in_use: 'ปิดใช้งานสำหรับการเข้าสู่ระบบ ',
  },
};

export default Object.freeze(connector_details);
