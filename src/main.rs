// main.rs

use iced::widget::{button, column, container, text, Image, Row};
use iced::{executor, Application, Command, Element, Length, Settings, Theme, Subscription};
use iced::time::Instant;
// --- Добавляем модули для работы с клавиатурой ---
use iced::keyboard;

// --- Зависимости для сети, криптографии и QR-кодов ---
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use aes::Aes128;
use aes::cipher::{
    BlockDecrypt, KeyInit,
    generic_array::GenericArray,
};
use qrcode_generator::QrCodeEcc;

// --- IP-адрес ESP32 в режиме точки доступа ---
const DEVICE_ADDRESS: &str = "192.168.4.1:80";

// --- Ключ для расшифровки AES (должен совпадать с ключом на ESP32) ---
const DECRYPTION_KEY: [u8; 16] = [
    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
    0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
];

pub fn main() -> iced::Result {
    TrngApp::run(Settings::default())
}

// --- Состояние приложения ---
struct TrngApp {
    status: String,
    generated_password: String,
    qr_code: Option<iced::widget::image::Handle>,
    is_generating: bool,
}

// --- Сообщения для обновления состояния ---
#[derive(Debug, Clone)]
enum Message {
    Generate,
    PasswordGenerated(Result<String, String>),
    RemoteControl(RemoteCommand),
    Tick(Instant),
}

#[derive(Debug, Clone)]
enum RemoteCommand {
    Up,
    Down,
    Select,
}

impl Application for TrngApp {
    type Executor = executor::Default;
    type Message = Message;
    type Theme = Theme;
    type Flags = ();

    fn new(_flags: ()) -> (Self, Command<Message>) {
        (
            Self {
                status: "Готово к подключению".to_string(),
                generated_password: "Ваш пароль появится здесь".to_string(),
                qr_code: None,
                is_generating: false,
            },
            Command::none(),
        )
    }

    fn title(&self) -> String {
        String::from("Ключник TRNG Client")
    }

    // --- Логика обновления состояния ---
    fn update(&mut self, message: Message) -> Command<Message> {
        match message {
            Message::Generate => {
                self.status = "Подключение и генерация...".to_string();
                self.is_generating = true;
                self.generated_password.clear();
                self.qr_code = None;

                Command::perform(generate_password_async(), Message::PasswordGenerated)
            }
            Message::PasswordGenerated(Ok(password)) => {
                self.status = "Пароль успешно сгенерирован!".to_string();
                self.generated_password = password.clone();
                
                let png_data = qrcode_generator::to_png_to_vec(password.as_bytes(), QrCodeEcc::Medium, 256).unwrap();
                let handle = iced::widget::image::Handle::from_memory(png_data);
                self.qr_code = Some(handle);
                self.is_generating = false;
                Command::none()
            }
            Message::PasswordGenerated(Err(e)) => {
                self.status = format!("Ошибка: {}", e);
                self.is_generating = false;
                Command::none()
            }
            Message::RemoteControl(cmd) => {
                // Отправляем команду и ничего не делаем в ответ
                Command::perform(send_remote_command(cmd), |_| Message::Tick(Instant::now()))
            }
            Message::Tick(_) => Command::none(),
        }
    }

    // --- Отрисовка интерфейса ---
    fn view(&self) -> Element<Message> {
        let title = text("Ключник: Квантово-устойчивый генератор паролей").size(24);
        let status_text = text(&self.status);

        let generate_button = if self.is_generating {
            button(text("Генерация...")).width(Length::Fill)
        } else {
            button(text("Подключиться и сгенерировать пароль"))
                .on_press(Message::Generate)
                .width(Length::Fill)
        };
        
        let password_display = text(&self.generated_password).size(20);

        let qr_display: Element<_> = if let Some(handle) = self.qr_code.clone() {
            Image::new(handle)
                .width(Length::Fixed(200.0))
                .height(Length::Fixed(200.0))
                .into()
        } else {
            container(text(""))
                .width(Length::Fixed(200.0))
                .height(Length::Fixed(200.0))
                .into()
        };

        let remote_controls = column![
            text("Удаленное управление").size(18),
            text("(Также работают стрелки и Enter/Пробел)"),
            button(text("Up")).on_press(Message::RemoteControl(RemoteCommand::Up)).width(Length::Fill),
            button(text("Down")).on_press(Message::RemoteControl(RemoteCommand::Down)).width(Length::Fill),
            button(text("Select")).on_press(Message::RemoteControl(RemoteCommand::Select)).width(Length::Fill),
        ].spacing(10);

        let main_content = column![
            title,
            status_text,
            generate_button,
            password_display,
        ]
        .spacing(20)
        .padding(20)
        .width(Length::Fill);

        let layout = Row::new()
            .push(main_content)
            .push(
                column![qr_display, remote_controls]
                .spacing(20)
                .padding(20)
                .width(Length::Shrink)
            )
            .align_items(iced::Alignment::Center);

        container(layout)
            .width(Length::Fill)
            .height(Length::Fill)
            .center_x()
            .center_y()
            .into()
    }
    
    fn theme(&self) -> Self::Theme {
        Theme::Dark
    }

    // --- ПОДПИСКА НА СОБЫТИЯ КЛАВИАТУРЫ ---
    fn subscription(&self) -> Subscription<Message> {
        keyboard::on_key_press(|key, _modifiers| {
            match key {
                keyboard::Key::Named(keyboard::key::Named::ArrowUp) => Some(Message::RemoteControl(RemoteCommand::Up)),
                keyboard::Key::Named(keyboard::key::Named::ArrowDown) => Some(Message::RemoteControl(RemoteCommand::Down)),
                keyboard::Key::Named(keyboard::key::Named::Enter) => Some(Message::RemoteControl(RemoteCommand::Select)),
                // --- ИСПРАВЛЕНИЕ ОШИБКИ ТИПОВ ---
                keyboard::Key::Character(s) if s == " " => Some(Message::RemoteControl(RemoteCommand::Select)),
                _ => None,
            }
        })
    }
}


// --- Асинхронная функция для сетевого взаимодействия и генерации пароля ---
async fn generate_password_async() -> Result<String, String> {
    let mut stream = TcpStream::connect(DEVICE_ADDRESS)
        .await
        .map_err(|e| format!("Не удалось подключиться: {}", e))?;
    
    stream.write_all(b"GET_DATA\n").await.map_err(|e| format!("Ошибка отправки запроса: {}", e))?;

    let mut buffer = [0; 128];
    let n = stream.read(&mut buffer).await.map_err(|e| format!("Ошибка чтения ответа: {}", e))?;
    let response = String::from_utf8_lossy(&buffer[..n]).to_string();

    let (len, complexity, encrypted_key) = parse_response(&response)?;

    let key_bytes = hex::decode(encrypted_key).map_err(|_| "Неверный формат HEX ключа".to_string())?;
    
    let cipher = Aes128::new(GenericArray::from_slice(&DECRYPTION_KEY));
    let mut decrypted_key = key_bytes.clone();
    cipher.decrypt_block(GenericArray::from_mut_slice(&mut decrypted_key));

    let password = generate_password_from_bytes(&decrypted_key, len, complexity);

    Ok(password)
}

// --- Парсер строки ответа от ESP32 ---
fn parse_response(response: &str) -> Result<(usize, u8, &str), String> {
    let parts: Vec<&str> = response.trim().split(',').collect();
    if parts.len() != 3 {
        return Err(format!("Неверный формат ответа ({} частей)", parts.len()));
    }
    
    let len_part = parts[0].strip_prefix("LEN:").ok_or("Отсутствует LEN")?;
    let len = len_part.parse::<usize>().map_err(|_| "Неверное значение LEN")?;

    let complex_part = parts[1].strip_prefix("COMPLEX:").ok_or("Отсутствует COMPLEX")?;
    let complexity = complex_part.parse::<u8>().map_err(|_| "Неверное значение COMPLEX")?;

    let key_part = parts[2].strip_prefix("KEY:").ok_or("Отсутствует KEY")?;

    Ok((len, complexity, key_part))
}

// --- Генератор пароля на основе случайных байт ---
fn generate_password_from_bytes(random_bytes: &[u8], length: usize, complexity: u8) -> String {
    const NUMBERS: &[u8] = b"0123456789";
    const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
    const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const SYMBOLS: &[u8] = b"!@#$%^&*()_+-=[]{}|;:,.<>?";

    let char_set = match complexity {
        0 => NUMBERS.to_vec(),
        1 => LOWERCASE.to_vec(),
        2 => UPPERCASE.to_vec(),
        3 => [LOWERCASE, UPPERCASE].concat(),
        4 => [LOWERCASE, UPPERCASE, NUMBERS].concat(),
        _ => [LOWERCASE, UPPERCASE, NUMBERS, SYMBOLS].concat(),
    };

    let mut password = String::with_capacity(length);
    for &byte in random_bytes.iter().cycle().take(length) {
        let index = byte as usize % char_set.len();
        password.push(char_set[index] as char);
    }

    password
}

// --- Отправка команды удаленного управления ---
async fn send_remote_command(cmd: RemoteCommand) {
    if let Ok(mut stream) = TcpStream::connect(DEVICE_ADDRESS).await {
        let cmd_str = match cmd {
            RemoteCommand::Up => "CMD_UP\n",
            RemoteCommand::Down => "CMD_DOWN\n",
            RemoteCommand::Select => "CMD_SELECT\n",
        };
        let _ = stream.write_all(cmd_str.as_bytes()).await;
    }
}
