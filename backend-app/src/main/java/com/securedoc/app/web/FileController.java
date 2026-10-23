package com.securedoc.app.web;

import com.securedoc.app.common.ApiResponse;
import com.securedoc.app.common.ClientIpResolver;
import com.securedoc.app.security.SecurityUser;
import com.securedoc.app.service.FileDownloadService;
import com.securedoc.app.service.FileQueryService;
import com.securedoc.app.service.FileUploadService;
import com.securedoc.app.web.dto.ChunkDownload;
import com.securedoc.app.web.dto.ChunkUploadResponse;
import com.securedoc.app.web.dto.FileSummary;
import com.securedoc.app.web.dto.InitUploadRequest;
import com.securedoc.app.web.dto.InitUploadResponse;
import com.securedoc.app.web.dto.KeyEnvelopeResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * 文件投递接口（§2.4 / §18.9）。应用服务器盲存储密文与信封，不接触明文与 SM4 密钥。
 */
@RestController
@RequestMapping("/api/files")
public class FileController {

    private final FileUploadService uploadService;
    private final FileQueryService queryService;
    private final FileDownloadService downloadService;
    private final ClientIpResolver clientIpResolver;

    public FileController(FileUploadService uploadService, FileQueryService queryService,
                          FileDownloadService downloadService, ClientIpResolver clientIpResolver) {
        this.uploadService = uploadService;
        this.queryService = queryService;
        this.downloadService = downloadService;
        this.clientIpResolver = clientIpResolver;
    }

    /** 初始化上传任务：登记文件与接收人信封，返回 fileId。 */
    @PostMapping("/init-upload")
    public ApiResponse<InitUploadResponse> initUpload(@Valid @RequestBody InitUploadRequest req,
                                                      @AuthenticationPrincipal SecurityUser user) {
        return ApiResponse.ok(uploadService.init(user.getUserId(), req));
    }

    /** 上传密文分块（raw 二进制 body）。头 X-Chunk-Digest 为客户端声明的 SM3 摘要，服务端核对。 */
    @PutMapping(value = "/{fileId}/chunks/{chunkIndex}", consumes = MediaType.APPLICATION_OCTET_STREAM_VALUE)
    public ApiResponse<ChunkUploadResponse> uploadChunk(
            @PathVariable String fileId,
            @PathVariable int chunkIndex,
            @RequestBody byte[] body,
            @RequestHeader(value = "X-Chunk-Digest", required = false) String chunkDigest,
            @RequestHeader(value = "X-Chunk-IV", required = false) String chunkIv,
            @AuthenticationPrincipal SecurityUser user) {
        return ApiResponse.ok(uploadService.uploadChunk(user.getUserId(), fileId, chunkIndex, body, chunkDigest, chunkIv));
    }

    /** 完成上传：全部分块就绪后置文件为 AVAILABLE。 */
    @PostMapping("/{fileId}/complete")
    public ApiResponse<InitUploadResponse> complete(@PathVariable String fileId,
                                                    @AuthenticationPrincipal SecurityUser user,
                                                    HttpServletRequest http) {
        return ApiResponse.ok(uploadService.complete(user.getUserId(), fileId, clientIpResolver.resolve(http)));
    }

    /** 收件箱：我作为接收人、已可下载(AVAILABLE)的文件。 */
    @GetMapping("/inbox")
    public ApiResponse<List<FileSummary>> inbox(@AuthenticationPrincipal SecurityUser user) {
        return ApiResponse.ok(queryService.inbox(user.getUserId()));
    }

    /** 发件箱：我发起的文件。 */
    @GetMapping("/outbox")
    public ApiResponse<List<FileSummary>> outbox(@AuthenticationPrincipal SecurityUser user) {
        return ApiResponse.ok(queryService.outbox(user.getUserId()));
    }

    /** 取我的密钥信封（仅接收人本人）。 */
    @GetMapping("/{fileId}/recipients/me/key-envelope")
    public ApiResponse<KeyEnvelopeResponse> keyEnvelope(@PathVariable String fileId,
                                                        @AuthenticationPrincipal SecurityUser user,
                                                        HttpServletRequest http) {
        return ApiResponse.ok(downloadService.getKeyEnvelope(user.getUserId(), fileId, clientIpResolver.resolve(http)));
    }

    /**
     * 下载密文分块（仅接收人本人）。返回 raw 二进制密文；响应头携带服务端存储的 SM3 摘要与 IV，
     * 浏览器解密前重算 SM3 比对（SM9-4 端到端防篡改）。非接收人/未就绪/越界由 service 抛错。
     */
    @GetMapping("/{fileId}/chunks/{chunkIndex}/download")
    public ResponseEntity<byte[]> downloadChunk(@PathVariable String fileId,
                                                @PathVariable int chunkIndex,
                                                @AuthenticationPrincipal SecurityUser user,
                                                HttpServletRequest http) {
        ChunkDownload dl = downloadService.downloadChunk(
                user.getUserId(), fileId, chunkIndex, clientIpResolver.resolve(http));

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);
        headers.set("X-Chunk-Index", String.valueOf(dl.chunkIndex()));
        headers.set("X-Chunk-Digest", dl.sm3Digest());
        if (dl.ivNonce() != null) {
            headers.set("X-Chunk-IV", dl.ivNonce());
        }
        // 让前端(跨域时)能读到上述自定义头以校验/解密
        headers.set(HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS, "X-Chunk-Index,X-Chunk-Digest,X-Chunk-IV");
        headers.setContentDisposition(ContentDisposition.attachment()
                .filename("chunk-" + chunkIndex + ".bin").build());
        return new ResponseEntity<>(dl.data(), headers, HttpStatus.OK);
    }
}
