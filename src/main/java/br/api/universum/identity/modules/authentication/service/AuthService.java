package br.api.universum.identity.modules.authentication.service;

import br.api.universum.identity.modules.authentication.dto.request.LoginRequest;
import br.api.universum.identity.modules.authentication.dto.request.RefreshTokenRequest;
import br.api.universum.identity.modules.authentication.dto.response.TokenResponse;
import br.api.universum.identity.modules.authentication.exception.InvalidCredentialsException;
import br.api.universum.identity.modules.authentication.exception.InvalidRefreshTokenException;
import br.api.universum.identity.modules.authentication.model.RefreshToken;
import br.api.universum.identity.modules.authentication.repository.RefreshTokenRepository;
import br.api.universum.identity.modules.user.exception.UserBlockedException;
import br.api.universum.identity.modules.user.exception.UserNotFoundException;
import br.api.universum.identity.modules.user.model.User;
import br.api.universum.identity.modules.user.repository.UserRepository;
import br.api.universum.identity.shared.exception.BusinessException;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private static final Duration REFRESH_TOKEN_VALIDITY = Duration.ofDays(7);

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final TokenService tokenService;
    private final PasswordEncoder passwordEncoder;

    @Transactional(noRollbackFor = BusinessException.class)
    public TokenResponse login(LoginRequest request) {
        User user = verifyCredentials(
                request.email(),
                request.password()
        );

        refreshTokenRepository.revokeAllByUserId(user.getId());

        return issueTokens(user);
    }

    // noRollbackFor: a revogação de todas as sessões em caso de reuso precisa ser persistida,
    // mesmo com a InvalidRefreshTokenException lançada em seguida.
    @Transactional(noRollbackFor = BusinessException.class)
    public TokenResponse refresh(RefreshTokenRequest request) {
        String tokenHash = tokenService.hashRefreshToken(request.refreshToken());
        RefreshToken current = refreshTokenRepository.findByTokenHash(tokenHash)
                .orElseThrow(InvalidRefreshTokenException::new);

        if (current.isRevoked()) {
            // Um refresh token já rotacionado voltou a ser apresentado: provável roubo.
            // Encerra todas as sessões do usuário, e o cliente precisa fazer login de novo.
            log.warn("[REFRESH] Reuso de refresh token revogado. Sessões do usuário {} encerradas",
                    current.getUserId());
            refreshTokenRepository.revokeAllByUserId(current.getUserId());
            throw new InvalidRefreshTokenException();
        }

        if (current.isExpired(Instant.now())) {
            throw new InvalidRefreshTokenException();
        }

        User user = userRepository.findById(current.getUserId()).orElseThrow(
                UserNotFoundException::new
        );

        current.revoke();

        if (user.isLocked(Instant.now())) {
            throw new UserBlockedException();
        }

        return issueTokens(user);
    }

    @Transactional
    public void logout(RefreshTokenRequest request) {
        String tokenHash = tokenService.hashRefreshToken(request.refreshToken());
        refreshTokenRepository.findByTokenHash(tokenHash).ifPresent(RefreshToken::revoke);
    }

    private User verifyCredentials(String email, String rawPassword) {

        log.info("[LOGIN] Login attempt started for email: '{}'", email);

        User user = userRepository.findByEmail(email).orElseThrow(
                () -> {
                    log.warn("[LOGIN] Login failed: email '{}' is not registered in the system", email);
                    return new InvalidCredentialsException();
                });

        Instant now = Instant.now();

        if (user.isLocked(now)) {
            log.warn("[LOGIN] Login failed: account '{}' " +
                    "is temporarily locked until {}", email, user.getLockExpiredAt());
            throw new UserBlockedException();
        }

        if (passwordEncoder.matches(rawPassword, user.getPassword())) {
            log.info("[LOGIN] Login succeeded for user: '{}' (ID: {})", email, user.getId());
            user.registerSuccessfulLogin();
            return user;
        }

        user.registerFailedLogin(now);

        if (user.isLocked(now)) {
            log.error("[LOGIN] Login failed: incorrect password for email '{}'. " +
                    "Attempt limit reached! Account temporarily LOCKED until {}", email, user.getLockExpiredAt());
            throw new UserBlockedException();
        }

        log.warn("[LOGIN] Login failed: incorrect password for email '{}'. " +
                "Consecutive failed attempts: {}/{}", email, user.getFailedAttempts(), User.MAX_FAILED_ATTEMPTS);
        throw new InvalidCredentialsException();
    }

    private TokenResponse issueTokens(User user) {
        String accessToken = tokenService.generateAccessToken(user);
        String refreshTokenValue = tokenService.generateRefreshToken();

        refreshTokenRepository.save(
                RefreshToken.issue(
                        tokenService.hashRefreshToken(refreshTokenValue),
                        user.getId(),
                        Instant.now(),
                        REFRESH_TOKEN_VALIDITY
                )
        );

        return TokenResponse.bearer(
                accessToken,
                refreshTokenValue,
                tokenService.getAccessTokenExpiresIn()
        );
    }
}
